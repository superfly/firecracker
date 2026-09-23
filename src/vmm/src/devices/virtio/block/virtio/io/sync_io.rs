// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sync file engine.
//!
//! The I/O itself is done with blocking system calls, but not on the thread that submits it: each
//! engine owns a worker thread that performs the requests one at a time, in submission order, and
//! reports each completion through an eventfd, the same way the async engine does. This keeps a
//! slow backing file from stalling the event loop, and with it every other device serviced there.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::sync::mpsc;
use std::thread;

use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::block::virtio::PendingRequest;
use crate::devices::virtio::block::virtio::io::RequestError;
use crate::logger::error;
use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap};

/// Maximum number of requests submitted to the worker and not yet popped. The engine reports
/// itself as throttled beyond this, and the device resumes processing its queue once completions
/// come back.
pub const SYNC_IO_MAX_IN_FLIGHT: usize = 128;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SyncIoError {
    /// Flush: {0}
    Flush(std::io::Error),
    /// Seek: {0}
    Seek(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// Transfer: {0}
    Transfer(GuestMemoryError),
    /// EventFd: {0}
    EventFd(std::io::Error),
    /// Cloning the backing file: {0}
    FileClone(std::io::Error),
    /// Spawning the IO worker thread: {0}
    Spawn(std::io::Error),
    /// Too many requests in flight
    QueueFull,
    /// The IO worker thread is gone
    WorkerGone,
}

/// A finished request, as reported by the worker thread.
#[derive(Debug)]
pub struct SyncCompletion {
    pub req: PendingRequest,
    pub result: Result<u32, SyncIoError>,
}

#[derive(Debug)]
enum Io {
    Read {
        offset: u64,
        mem: GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    },
    Write {
        offset: u64,
        mem: GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    },
    Flush,
}

#[derive(Debug)]
enum Op {
    Io {
        io: Io,
        req: PendingRequest,
    },
    /// Switch to a new backing file. Requests submitted before it use the old one.
    UpdateFile(File),
    /// Acknowledged once every request submitted before it has completed.
    Barrier(mpsc::SyncSender<()>),
    Exit,
}

/// Blocking I/O on the backing file. Only ever used from the worker thread.
#[derive(Debug)]
struct BlockingFile {
    file: File,
}

impl BlockingFile {
    fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(self.file.read_exact_volatile(&mut slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        mem.get_slice(addr, count as usize)
            .and_then(|slice| Ok(self.file.write_all_volatile(&slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }

    fn execute(&mut self, io: Io) -> Result<u32, SyncIoError> {
        match io {
            Io::Read {
                offset,
                mem,
                addr,
                count,
            } => {
                let count = self.read(offset, &mem, addr, count)?;
                // The guest memory was written from this thread, so account for it in the dirty
                // bitmap before the device gets to see the completion.
                mem.mark_dirty(addr, count as usize);
                Ok(count)
            }
            Io::Write {
                offset,
                mem,
                addr,
                count,
            } => self.write(offset, &mem, addr, count),
            Io::Flush => self.flush().map(|_| 0),
        }
    }
}

fn run_worker(
    mut file: BlockingFile,
    ops: mpsc::Receiver<Op>,
    completions: mpsc::Sender<SyncCompletion>,
    completion_evt: EventFd,
) {
    if let Some(filter) = crate::seccomp::block_io_filter()
        && let Err(err) = crate::seccomp::apply_filter(filter)
    {
        panic!("Failed to set the requested seccomp filters on the block IO worker: {err}");
    }

    for op in ops {
        let completion = match op {
            Op::Io { io, req } => SyncCompletion {
                req,
                result: file.execute(io),
            },
            Op::UpdateFile(new_file) => {
                file.file = new_file;
                continue;
            }
            Op::Barrier(ack) => {
                // The submitter may have given up waiting; nothing to do about it here.
                let _ = ack.send(());
                continue;
            }
            Op::Exit => break,
        };

        if completions.send(completion).is_err() {
            break;
        }
        if let Err(err) = completion_evt.write(1) {
            error!("Failed to signal block IO completion: {:?}", err);
        }
    }
}

/// Front end of the sync engine, used from the thread that owns the device.
#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
    ops: mpsc::Sender<Op>,
    completions: mpsc::Receiver<SyncCompletion>,
    completion_evt: EventFd,
    in_flight: usize,
    worker: Option<thread::JoinHandle<()>>,
}

impl SyncFileEngine {
    pub fn from_file(file: File) -> Result<SyncFileEngine, SyncIoError> {
        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(SyncIoError::EventFd)?;
        let worker_evt = completion_evt.try_clone().map_err(SyncIoError::EventFd)?;
        let worker_file = BlockingFile {
            file: file.try_clone().map_err(SyncIoError::FileClone)?,
        };
        let (ops, worker_ops) = mpsc::channel();
        let (worker_completions, completions) = mpsc::channel();

        let worker = thread::Builder::new()
            .name("fc_blk_io".to_string())
            .spawn(move || run_worker(worker_file, worker_ops, worker_completions, worker_evt))
            .map_err(SyncIoError::Spawn)?;

        Ok(SyncFileEngine {
            file,
            ops,
            completions,
            completion_evt,
            in_flight: 0,
            worker: Some(worker),
        })
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File) -> Result<(), SyncIoError> {
        let worker_file = file.try_clone().map_err(SyncIoError::FileClone)?;
        self.ops
            .send(Op::UpdateFile(worker_file))
            .map_err(|_| SyncIoError::WorkerGone)?;
        self.file = file;
        Ok(())
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    fn push(&mut self, io: Io, req: PendingRequest) -> Result<(), RequestError<SyncIoError>> {
        if self.in_flight >= SYNC_IO_MAX_IN_FLIGHT {
            return Err(RequestError {
                req,
                error: SyncIoError::QueueFull,
            });
        }

        match self.ops.send(Op::Io { io, req }) {
            Ok(()) => {
                self.in_flight += 1;
                Ok(())
            }
            Err(mpsc::SendError(Op::Io { req, .. })) => Err(RequestError {
                req,
                error: SyncIoError::WorkerGone,
            }),
            Err(_) => unreachable!("sent an IO op"),
        }
    }

    pub fn push_read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<SyncIoError>> {
        let io = Io::Read {
            offset,
            mem: mem.clone(),
            addr,
            count,
        };
        self.push(io, req)
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<SyncIoError>> {
        let io = Io::Write {
            offset,
            mem: mem.clone(),
            addr,
            count,
        };
        self.push(io, req)
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<SyncIoError>> {
        self.push(Io::Flush, req)
    }

    /// Pop a finished request, if there is one.
    pub fn pop(&mut self) -> Option<SyncCompletion> {
        let completion = self.completions.try_recv().ok()?;
        self.in_flight -= 1;
        Some(completion)
    }

    /// Wait for every submitted request to complete. Their completions are left to be popped,
    /// unless `discard` is set.
    pub fn drain(&mut self, discard: bool) -> Result<(), SyncIoError> {
        if self.in_flight > 0 {
            let (ack, done) = mpsc::sync_channel(1);
            self.ops
                .send(Op::Barrier(ack))
                .map_err(|_| SyncIoError::WorkerGone)?;
            done.recv().map_err(|_| SyncIoError::WorkerGone)?;
        }

        if discard {
            while self.pop().is_some() {}
        }

        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), SyncIoError> {
        self.drain(discard)?;

        // Sync data out to physical media on host. The worker holds no data of its own, so the
        // file descriptor here reaches everything it wrote.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }
}

impl Drop for SyncFileEngine {
    fn drop(&mut self) {
        // The worker only exits once it gets here, so everything submitted before is finished.
        let _ = self.ops.send(Op::Exit);
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            error!("The block IO worker thread panicked");
        }
    }
}
