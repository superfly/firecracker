// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Threaded file engine.
//!
//! Blocking I/O, like the sync engine, but not on the thread that submits it: each engine owns a
//! worker thread that performs the requests one at a time, in submission order, and reports
//! completions through an eventfd, the way the async engine does. A slow backing file then stalls
//! only its own worker, not the event loop and every other device serviced there, and no
//! io_uring support is needed.

use std::fs::File;
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use vmm_sys_util::eventfd::EventFd;

use super::sync_io::{SyncFileEngine, SyncIoError};
use crate::devices::virtio::block::virtio::PendingRequest;
use crate::devices::virtio::block::virtio::io::RequestError;
use crate::logger::error;
use crate::seccomp::{BpfProgram, BpfProgramRef};
use crate::vstate::memory::{GuestAddress, GuestMemoryExtension, GuestMemoryMmap};

/// Maximum number of requests submitted to the worker and not yet popped. The engine reports
/// itself as throttled beyond this, and the device resumes processing its queue once completions
/// come back.
pub const THREADED_IO_MAX_IN_FLIGHT: usize = 128;

/// How long a finished request may wait for the requests queued behind it before the device is
/// told about it.
const COMPLETION_SIGNAL_DELAY: Duration = Duration::from_micros(200);

/// Filter the worker threads apply to themselves, see [`set_worker_seccomp_filter`].
static WORKER_SECCOMP_FILTER: OnceLock<Arc<BpfProgram>> = OnceLock::new();

/// Set the seccomp filter each worker thread applies to itself when it starts.
///
/// Workers are started whenever a drive is created, which is before the VMM thread installs its
/// own filter, so they cannot rely on inheriting it. Only the first call has an effect.
pub fn set_worker_seccomp_filter(filter: Arc<BpfProgram>) {
    // Ignoring the error is what makes later calls no-ops.
    let _ = WORKER_SECCOMP_FILTER.set(filter);
}

fn worker_seccomp_filter() -> Option<BpfProgramRef<'static>> {
    WORKER_SECCOMP_FILTER.get().map(|filter| filter.as_slice())
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ThreadedIoError {
    /// IO: {0}
    Io(SyncIoError),
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
pub struct ThreadedCompletion {
    pub req: PendingRequest,
    pub result: Result<u32, ThreadedIoError>,
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

impl Io {
    fn execute(self, file: &mut SyncFileEngine) -> Result<u32, SyncIoError> {
        match self {
            Io::Read {
                offset,
                mem,
                addr,
                count,
            } => {
                let count = file.read(offset, &mem, addr, count)?;
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
            } => file.write(offset, &mem, addr, count),
            Io::Flush => file.flush().map(|_| 0),
        }
    }
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

/// Coalesces the completion eventfd writes of the worker thread.
#[derive(Debug)]
struct CompletionSignal {
    evt: EventFd,
    pending: bool,
    last: Instant,
}

impl CompletionSignal {
    fn new(evt: EventFd) -> Self {
        CompletionSignal {
            evt,
            pending: false,
            last: Instant::now(),
        }
    }

    /// Signal pending completions if the last signal is old enough.
    fn maybe_flush(&mut self) {
        if self.last.elapsed() >= COMPLETION_SIGNAL_DELAY {
            self.flush();
        }
    }

    /// Signal pending completions.
    fn flush(&mut self) {
        if !self.pending {
            return;
        }
        if let Err(err) = self.evt.write(1) {
            error!("Failed to signal block IO completion: {:?}", err);
        }
        self.pending = false;
        self.last = Instant::now();
    }
}

fn run_worker(
    mut file: SyncFileEngine,
    ops: mpsc::Receiver<Op>,
    completions: mpsc::Sender<ThreadedCompletion>,
    completion_evt: EventFd,
) {
    if let Some(filter) = worker_seccomp_filter()
        && let Err(err) = crate::seccomp::apply_filter(filter)
    {
        panic!("Failed to set the requested seccomp filters on the block IO worker: {err}");
    }

    let mut signal = CompletionSignal::new(completion_evt);
    let mut next = None;
    loop {
        let op = match next.take() {
            Some(op) => op,
            None => {
                // Never go to sleep on a completion the device has not been told about.
                signal.flush();
                match ops.recv() {
                    Ok(op) => op,
                    Err(mpsc::RecvError) => break,
                }
            }
        };

        let completion = match op {
            Op::Io { io, req } => ThreadedCompletion {
                req,
                result: io.execute(&mut file).map_err(ThreadedIoError::Io),
            },
            Op::UpdateFile(new_file) => {
                file.update_file(new_file);
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
        signal.pending = true;

        // Hold the signal back while more requests are queued, so that the device handles a
        // burst of completions at once instead of raising an interrupt for each. Only while the
        // previous signal is recent, though: a slow backing file gets one after every request.
        match ops.try_recv() {
            Ok(op) => {
                next = Some(op);
                signal.maybe_flush();
            }
            Err(_) => signal.flush(),
        }
    }
    signal.flush();
}

/// Front end of the threaded engine, used from the thread that owns the device.
#[derive(Debug)]
pub struct ThreadedFileEngine {
    file: File,
    ops: mpsc::Sender<Op>,
    completions: mpsc::Receiver<ThreadedCompletion>,
    completion_evt: EventFd,
    in_flight: usize,
    worker: Option<thread::JoinHandle<()>>,
}

impl ThreadedFileEngine {
    pub fn from_file(file: File) -> Result<ThreadedFileEngine, ThreadedIoError> {
        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(ThreadedIoError::EventFd)?;
        let worker_evt = completion_evt
            .try_clone()
            .map_err(ThreadedIoError::EventFd)?;
        let worker_file =
            SyncFileEngine::from_file(file.try_clone().map_err(ThreadedIoError::FileClone)?);
        let (ops, worker_ops) = mpsc::channel();
        let (worker_completions, completions) = mpsc::channel();

        let worker = thread::Builder::new()
            .name("fc_blk_io".to_string())
            .spawn(move || run_worker(worker_file, worker_ops, worker_completions, worker_evt))
            .map_err(ThreadedIoError::Spawn)?;

        Ok(ThreadedFileEngine {
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
    pub fn update_file(&mut self, file: File) -> Result<(), ThreadedIoError> {
        let worker_file = file.try_clone().map_err(ThreadedIoError::FileClone)?;
        self.ops
            .send(Op::UpdateFile(worker_file))
            .map_err(|_| ThreadedIoError::WorkerGone)?;
        self.file = file;
        Ok(())
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    fn push(&mut self, io: Io, req: PendingRequest) -> Result<(), RequestError<ThreadedIoError>> {
        if self.in_flight >= THREADED_IO_MAX_IN_FLIGHT {
            return Err(RequestError {
                req,
                error: ThreadedIoError::QueueFull,
            });
        }

        match self.ops.send(Op::Io { io, req }) {
            Ok(()) => {
                self.in_flight += 1;
                Ok(())
            }
            Err(mpsc::SendError(Op::Io { req, .. })) => Err(RequestError {
                req,
                error: ThreadedIoError::WorkerGone,
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
    ) -> Result<(), RequestError<ThreadedIoError>> {
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
    ) -> Result<(), RequestError<ThreadedIoError>> {
        let io = Io::Write {
            offset,
            mem: mem.clone(),
            addr,
            count,
        };
        self.push(io, req)
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<ThreadedIoError>> {
        self.push(Io::Flush, req)
    }

    /// Pop a finished request, if there is one.
    pub fn pop(&mut self) -> Option<ThreadedCompletion> {
        let completion = self.completions.try_recv().ok()?;
        self.in_flight -= 1;
        Some(completion)
    }

    /// Wait for every submitted request to complete. Their completions are left to be popped,
    /// unless `discard` is set.
    pub fn drain(&mut self, discard: bool) -> Result<(), ThreadedIoError> {
        if self.in_flight > 0 {
            let (ack, done) = mpsc::sync_channel(1);
            self.ops
                .send(Op::Barrier(ack))
                .map_err(|_| ThreadedIoError::WorkerGone)?;
            done.recv().map_err(|_| ThreadedIoError::WorkerGone)?;
        }

        if discard {
            while self.pop().is_some() {}
        }

        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), ThreadedIoError> {
        self.drain(discard)?;

        // Sync data out to physical media on host. The worker holds no data of its own, so the
        // file descriptor here reaches everything it wrote.
        self.file
            .sync_all()
            .map_err(|err| ThreadedIoError::Io(SyncIoError::SyncAll(err)))
    }
}

impl Drop for ThreadedFileEngine {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    use vm_memory::GuestMemoryRegion;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::utils::u64_to_usize;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemory, GuestRegionMmapExt};

    const FILE_LEN: u32 = 1024;
    // 2 pages of memory should be enough to test read/write ops and also dirty tracking.
    const MEM_LEN: usize = 8192;

    fn create_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            memory::anonymous(
                [(GuestAddress(0), MEM_LEN)].into_iter(),
                true,
                HugePageConfig::None,
            )
            .unwrap()
            .into_iter()
            .map(|region| GuestRegionMmapExt::dram_from_mmap_region(region, 0))
            .collect(),
        )
        .unwrap()
    }

    fn check_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32, dirty: bool) {
        let bitmap = mem.find_region(addr).unwrap().bitmap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert_eq!(bitmap.dirty_at(u64_to_usize(offset)), dirty);
        }
    }

    fn new_engine() -> ThreadedFileEngine {
        ThreadedFileEngine::from_file(TempFile::new().unwrap().into_file()).unwrap()
    }

    fn assert_completed(engine: &mut ThreadedFileEngine, count: u32) {
        engine.drain(false).unwrap();
        assert_eq!(engine.pop().unwrap().result.unwrap(), count);
    }

    fn wait_for_signal(engine: &ThreadedFileEngine) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while engine.completion_evt().read().is_err() {
            assert!(Instant::now() < deadline, "completion never signalled");
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn test_read_write_flush() {
        let mut engine = new_engine();
        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write and read, at the end of guest memory.
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - u64::from(partial_len));
        let mem = create_mem();
        mem.write(&data, addr).unwrap();
        engine
            .push_write(0, &mem, addr, partial_len, PendingRequest::default())
            .unwrap();
        assert_completed(&mut engine, partial_len);
        let mem = create_mem();
        engine
            .push_read(0, &mem, addr, partial_len, PendingRequest::default())
            .unwrap();
        assert_completed(&mut engine, partial_len);
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Full write and read, at an offset.
        let mem = create_mem();
        mem.write(&data, GuestAddress(0)).unwrap();
        engine
            .push_write(
                100,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        assert_completed(&mut engine, FILE_LEN);
        let mem = create_mem();
        engine
            .push_read(
                100,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        assert_completed(&mut engine, FILE_LEN);
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data);

        // Reads from the worker thread are accounted for in the dirty bitmap.
        check_dirty_mem(&mem, GuestAddress(0), FILE_LEN, true);
        check_dirty_mem(&mem, GuestAddress(4096), 4096, false);

        // Out of bounds guest memory fails the request, not the engine.
        engine
            .push_read(
                0,
                &mem,
                GuestAddress(MEM_LEN as u64),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        engine.drain(false).unwrap();
        assert!(matches!(
            engine.pop().unwrap().result,
            Err(ThreadedIoError::Io(SyncIoError::Transfer(_)))
        ));

        engine.push_flush(PendingRequest::default()).unwrap();
        assert_completed(&mut engine, 0);
        engine.drain_and_flush(true).unwrap();
    }

    #[test]
    fn test_completions_are_signalled() {
        let mem = create_mem();
        let mut engine = new_engine();

        // Submitting returns before the IO is done: completions only show up through the
        // completion eventfd, once the worker has finished them.
        for _ in 0..10 {
            engine
                .push_write(
                    0,
                    &mem,
                    GuestAddress(0),
                    FILE_LEN,
                    PendingRequest::default(),
                )
                .unwrap();
        }
        let mut completed = 0;
        while completed < 10 {
            wait_for_signal(&engine);
            while let Some(completion) = engine.pop() {
                assert_eq!(completion.result.unwrap(), FILE_LEN);
                completed += 1;
            }
        }
        assert!(engine.pop().is_none());
    }

    #[test]
    fn test_signal_before_idle() {
        let mem = create_mem();
        let mut engine = new_engine();

        // Queue ops that complete nothing behind a request: the worker must still signal the
        // request's completion before it goes idle.
        engine
            .push_write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        engine
            .update_file(TempFile::new().unwrap().into_file())
            .unwrap();

        wait_for_signal(&engine);
        assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
    }

    #[test]
    fn test_throttling() {
        let mut engine = new_engine();

        for _ in 0..THREADED_IO_MAX_IN_FLIGHT {
            engine.push_flush(PendingRequest::default()).unwrap();
        }
        // Completed but not yet popped requests still count as in flight.
        engine.drain(false).unwrap();
        let err = engine.push_flush(PendingRequest::default()).unwrap_err();
        assert!(matches!(err.error, ThreadedIoError::QueueFull));

        // Popping a completion makes room for one more request.
        engine.pop().unwrap();
        engine.push_flush(PendingRequest::default()).unwrap();
        let err = engine.push_flush(PendingRequest::default()).unwrap_err();
        assert!(matches!(err.error, ThreadedIoError::QueueFull));

        // Discarding all completions makes room for all of them.
        engine.drain(true).unwrap();
        assert!(engine.pop().is_none());
        for _ in 0..THREADED_IO_MAX_IN_FLIGHT {
            engine.push_flush(PendingRequest::default()).unwrap();
        }
        engine.drain(true).unwrap();
    }

    #[test]
    fn test_update_file() {
        let mem = create_mem();
        let old = TempFile::new().unwrap();
        let new = TempFile::new().unwrap();
        let mut engine = ThreadedFileEngine::from_file(old.as_file().try_clone().unwrap()).unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();
        mem.write(&data, GuestAddress(0)).unwrap();

        // Requests submitted before the update go to the old file, the ones after to the new one,
        // without waiting for the first to complete.
        engine
            .push_write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        engine
            .update_file(new.as_file().try_clone().unwrap())
            .unwrap();
        engine
            .push_write(0, &mem, GuestAddress(0), 10, PendingRequest::default())
            .unwrap();
        engine.drain(true).unwrap();

        assert_eq!(old.as_file().metadata().unwrap().len(), u64::from(FILE_LEN));
        assert_eq!(new.as_file().metadata().unwrap().len(), 10);
        assert_eq!(
            engine.file().metadata().unwrap().ino(),
            new.as_file().metadata().unwrap().ino()
        );
    }
}
