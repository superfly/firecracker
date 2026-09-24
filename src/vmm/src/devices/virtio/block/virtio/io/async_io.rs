// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::fs::File;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;

use vm_memory::GuestMemoryError;
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::block::virtio::io::{
    AlignedBuf, DirectIoError, RequestError, direct_io_bounce,
};
use crate::devices::virtio::block::virtio::{IO_URING_NUM_ENTRIES, PendingRequest};
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::{error, log_dev_preview_warning};
use crate::vstate::memory::{
    Bytes, GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap,
};

const MAX_OUTSTANDING_OPS: u32 = 16;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AsyncIoError {
    /// Direct I/O: {0}
    DirectIo(DirectIoError),
    /// IO: {0}
    IO(std::io::Error),
    /// IoUring: {0}
    IoUring(IoUringError),
    /// Submit: {0}
    Submit(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// EventFd: {0}
    EventFd(std::io::Error),
    /// GuestMemory: {0}
    GuestMemory(GuestMemoryError),
}

#[derive(Debug)]
pub struct AsyncFileEngine {
    file: File,
    ring: IoUring<WrappedRequest>,
    completion_evt: EventFd,
    direct_align: Option<u32>,
}

#[derive(Debug)]
pub struct WrappedRequest {
    addr: Option<GuestAddress>,
    req: PendingRequest,
    // Aligned buffer the kernel reads from or writes to in place of guest memory.
    // It must outlive the operation, so it travels with the request.
    bounce: Option<AlignedBuf>,
}

impl WrappedRequest {
    fn new(req: PendingRequest, bounce: Option<AlignedBuf>) -> Self {
        WrappedRequest {
            addr: None,
            req,
            bounce,
        }
    }

    fn new_with_dirty_tracking(
        addr: GuestAddress,
        req: PendingRequest,
        bounce: Option<AlignedBuf>,
    ) -> Self {
        WrappedRequest {
            addr: Some(addr),
            req,
            bounce,
        }
    }

    /// Completes a read into guest memory. Returns false if a bounced read could not be copied.
    fn mark_dirty_mem_and_unwrap(
        self,
        mem: &GuestMemoryMmap,
        count: u32,
    ) -> (PendingRequest, bool) {
        let mut copied = true;
        if let Some(addr) = self.addr {
            if let Some(bounce) = &self.bounce {
                let data = &bounce.as_slice()[..(count as usize).min(bounce.as_slice().len())];
                if let Err(err) = mem.write_slice(data, addr) {
                    error!("Failed to copy direct I/O bounce buffer to guest memory: {err}");
                    copied = false;
                }
            }
            mem.mark_dirty(addr, count as usize)
        }

        (self.req, copied)
    }
}

impl AsyncFileEngine {
    fn new_ring(
        file: &File,
        completion_fd: RawFd,
    ) -> Result<IoUring<WrappedRequest>, IoUringError> {
        IoUring::new(
            u32::from(IO_URING_NUM_ENTRIES),
            vec![file],
            vec![
                // Make sure we only allow operations on pre-registered fds.
                Restriction::RequireFixedFds,
                // Allowlist of opcodes.
                Restriction::AllowOpCode(OpCode::Read),
                Restriction::AllowOpCode(OpCode::Write),
                Restriction::AllowOpCode(OpCode::Fsync),
            ],
            Some(completion_fd),
        )
    }

    pub fn from_file(
        file: File,
        direct_align: Option<u32>,
    ) -> Result<AsyncFileEngine, AsyncIoError> {
        log_dev_preview_warning("Async file IO", Option::None);

        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(AsyncIoError::EventFd)?;
        let ring =
            Self::new_ring(&file, completion_evt.as_raw_fd()).map_err(AsyncIoError::IoUring)?;

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            direct_align,
        })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    pub fn is_throttled(&self) -> bool {
        // Include queued operations and completions not yet consumed by the device.
        self.ring.num_ops() >= MAX_OUTSTANDING_OPS
    }

    /// Returns a bounce buffer if a direct I/O request cannot use the guest buffer in place.
    fn direct_bounce(
        &self,
        offset: u64,
        host_addr: usize,
        count: u32,
    ) -> Result<Option<AlignedBuf>, DirectIoError> {
        match self.direct_align {
            Some(align) => direct_io_bounce(align, offset, host_addr, count),
            None => Ok(None),
        }
    }

    pub fn push_read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr(),
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };

        let mut bounce = match self.direct_bounce(offset, buf as usize, count) {
            Ok(bounce) => bounce,
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::DirectIo(err),
                });
            }
        };
        // The kernel writes the read into the bounce buffer, so take a mutable pointer.
        let target = bounce
            .as_mut()
            .map_or(buf as usize, |b| b.as_mut_slice().as_mut_ptr() as usize);
        let wrapped_user_data = WrappedRequest::new_with_dirty_tracking(addr, req, bounce);

        self.ring
            .push(Operation::read(0, target, count, offset, wrapped_user_data))
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let buf = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr(),
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };

        let mut bounce = match self.direct_bounce(offset, buf as usize, count) {
            Ok(bounce) => bounce,
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::DirectIo(err),
                });
            }
        };
        if let Some(bounce) = bounce.as_mut()
            && let Err(err) = mem.read_slice(bounce.as_mut_slice(), addr)
        {
            return Err(RequestError {
                req,
                error: AsyncIoError::GuestMemory(err),
            });
        }
        let source = bounce
            .as_ref()
            .map_or(buf as usize, |b| b.as_slice().as_ptr() as usize);
        let wrapped_user_data = WrappedRequest::new(req, bounce);

        self.ring
            .push(Operation::write(
                0,
                source,
                count,
                offset,
                wrapped_user_data,
            ))
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<AsyncIoError>> {
        let wrapped_user_data = WrappedRequest::new(req, None);

        self.ring
            .push(Operation::fsync(0, wrapped_user_data))
            .map_err(|(io_uring_error, data)| RequestError {
                req: data.req,
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    pub fn kick_submission_queue(&mut self) -> Result<(), AsyncIoError> {
        self.ring
            .submit()
            .map(|_| ())
            .map_err(AsyncIoError::IoUring)
    }

    pub fn drain(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.ring
            .submit_and_wait_all()
            .map(|_| ())
            .map_err(AsyncIoError::IoUring)?;

        if discard_cqes {
            // Drain the completion queue so that we may deallocate the user_data fields.
            while self.do_pop()?.is_some() {}
        }

        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.drain(discard_cqes)?;

        // Sync data out to physical media on host.
        // We don't need to call flush first since all the ops are performed through io_uring
        // and Rust shouldn't manage any data in its internal buffers.
        self.file.sync_all().map_err(AsyncIoError::SyncAll)?;

        Ok(())
    }

    fn do_pop(&mut self) -> Result<Option<Cqe<WrappedRequest>>, AsyncIoError> {
        self.ring.pop().map_err(AsyncIoError::IoUring)
    }

    pub fn pop(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<Option<Cqe<PendingRequest>>, AsyncIoError> {
        let cqe = self.do_pop()?.map(|cqe| {
            let count = cqe.count();
            let mut copied = true;
            let cqe = cqe.map_user_data(|wrapped_user_data| {
                let (req, ok) = wrapped_user_data.mark_dirty_mem_and_unwrap(mem, count);
                copied = ok;
                req
            });
            // Never report success for a read whose data did not reach the guest.
            if copied {
                cqe
            } else {
                Cqe::new(-libc::EIO, cqe.user_data())
            }
        });

        Ok(cqe)
    }
}
