// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod async_io;
pub mod nbd_io;
pub mod sync_io;
pub mod threaded_io;

use std::fmt::Debug;
use std::fs::File;
use std::sync::{Arc, Mutex};

pub use self::async_io::{AsyncFileEngine, AsyncIoError};
pub use self::nbd_io::{NbdBackendConfig, NbdFileEngine, NbdIoError};
pub use self::sync_io::{SyncFileEngine, SyncIoError};
pub use self::threaded_io::{ThreadedFileEngine, ThreadedIoError};
use crate::devices::virtio::block::virtio::PendingRequest;
use crate::devices::virtio::block::virtio::device::FileEngineType;
use crate::devices::virtio::queue::Queue;
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

#[derive(Debug)]
pub struct RequestOk {
    pub req: PendingRequest,
    pub count: u32,
}

#[derive(Debug)]
pub enum FileEngineOk {
    Submitted,
    Executed(RequestOk),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockIoError {
    /// Sync error: {0}
    Sync(SyncIoError),
    /// Async error: {0}
    Async(AsyncIoError),
    /// Threaded error: {0}
    Threaded(ThreadedIoError),
    /// NBD error: {0}
    Nbd(NbdIoError),
}

impl BlockIoError {
    pub fn is_throttling_err(&self) -> bool {
        match self {
            BlockIoError::Async(AsyncIoError::IoUring(err)) => err.is_throttling_err(),
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct RequestError<E> {
    pub req: PendingRequest,
    pub error: E,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FileEngine {
    #[allow(unused)]
    Async(AsyncFileEngine),
    Sync(SyncFileEngine),
    Threaded(ThreadedFileEngine),
    Nbd(NbdFileEngine),
}

impl FileEngine {
    pub fn from_file(file: File, engine_type: FileEngineType) -> Result<FileEngine, BlockIoError> {
        match engine_type {
            FileEngineType::Async => Ok(FileEngine::Async(
                AsyncFileEngine::from_file(file).map_err(BlockIoError::Async)?,
            )),
            FileEngineType::Sync => Ok(FileEngine::Sync(SyncFileEngine::from_file(file))),
            FileEngineType::Threaded => Ok(FileEngine::Threaded(
                ThreadedFileEngine::from_file(file).map_err(BlockIoError::Threaded)?,
            )),
            FileEngineType::Nbd => Err(BlockIoError::Nbd(NbdIoError::NoBackingFile)),
        }
    }

    pub fn update_file_path(&mut self, file: File) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine.update_file(file).map_err(BlockIoError::Async)?,
            FileEngine::Sync(engine) => engine.update_file(file),
            FileEngine::Threaded(engine) => {
                engine.update_file(file).map_err(BlockIoError::Threaded)?
            }
            FileEngine::Nbd(engine) => engine.update_file(file).map_err(BlockIoError::Nbd)?,
        };

        Ok(())
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        match self {
            FileEngine::Async(engine) => engine.file(),
            FileEngine::Sync(engine) => engine.file(),
            FileEngine::Threaded(engine) => engine.file(),
            FileEngine::Nbd(_) => panic!("A drive served over NBD has no backing file"),
        }
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.push_read(offset, mem, addr, count, req) {
                Ok(_) => Ok(FileEngineOk::Submitted),
                Err(err) => Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Async(err.error),
                }),
            },
            FileEngine::Threaded(_) => {
                let err = ThreadedFileEngine::refuse(req);
                Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Threaded(err.error),
                })
            }
            FileEngine::Nbd(_) => {
                let err = NbdFileEngine::refuse(req);
                Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Nbd(err.error),
                })
            }
            FileEngine::Sync(engine) => match engine.read(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
        }
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.push_write(offset, mem, addr, count, req) {
                Ok(_) => Ok(FileEngineOk::Submitted),
                Err(err) => Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Async(err.error),
                }),
            },
            FileEngine::Threaded(_) => {
                let err = ThreadedFileEngine::refuse(req);
                Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Threaded(err.error),
                })
            }
            FileEngine::Nbd(_) => {
                let err = NbdFileEngine::refuse(req);
                Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Nbd(err.error),
                })
            }
            FileEngine::Sync(engine) => match engine.write(offset, mem, addr, count) {
                Ok(count) => Ok(FileEngineOk::Executed(RequestOk { req, count })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
        }
    }

    pub fn flush(
        &mut self,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => match engine.push_flush(req) {
                Ok(_) => Ok(FileEngineOk::Submitted),
                Err(err) => Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Async(err.error),
                }),
            },
            FileEngine::Threaded(_) => {
                let err = ThreadedFileEngine::refuse(req);
                Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Threaded(err.error),
                })
            }
            FileEngine::Nbd(_) => {
                let err = NbdFileEngine::refuse(req);
                Err(RequestError {
                    req: err.req,
                    error: BlockIoError::Nbd(err.error),
                })
            }
            FileEngine::Sync(engine) => match engine.flush() {
                Ok(_) => Ok(FileEngineOk::Executed(RequestOk { req, count: 0 })),
                Err(err) => Err(RequestError {
                    req,
                    error: BlockIoError::Sync(err),
                }),
            },
        }
    }

    pub fn drain(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine.drain(discard).map_err(BlockIoError::Async),
            FileEngine::Sync(_engine) => Ok(()),
            FileEngine::Threaded(engine) => engine.drain(discard).map_err(BlockIoError::Threaded),
            FileEngine::Nbd(engine) => engine.drain(discard).map_err(BlockIoError::Nbd),
        }
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => {
                engine.drain_and_flush(discard).map_err(BlockIoError::Async)
            }
            FileEngine::Sync(engine) => engine.flush().map_err(BlockIoError::Sync),
            FileEngine::Threaded(engine) => engine
                .drain_and_flush(discard)
                .map_err(BlockIoError::Threaded),
            FileEngine::Nbd(engine) => engine.drain_and_flush(discard).map_err(BlockIoError::Nbd),
        }
    }

    /// The engine's worker thread, for engines whose worker serves the queue itself.
    pub fn queue_worker(&self) -> Option<&dyn QueueWorker> {
        match self {
            FileEngine::Threaded(engine) => Some(engine),
            FileEngine::Nbd(engine) => Some(engine),
            _ => None,
        }
    }

    pub fn queue_worker_mut(&mut self) -> Option<&mut dyn QueueWorker> {
        match self {
            FileEngine::Threaded(engine) => Some(engine),
            FileEngine::Nbd(engine) => Some(engine),
            _ => None,
        }
    }
}

/// An engine whose worker thread takes the device's queue, and serves it, from activation on.
pub trait QueueWorker: Debug {
    /// Whether the worker serves the device's queue.
    fn is_serving(&self) -> bool;
    /// Hand the device's queue and rate limiter to the worker.
    fn start(
        &mut self,
        serving: threaded_io::Serving,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<(), BlockIoError>;
    /// Take the queue and the rate limiter back. The NBD engine first waits for the requests in
    /// flight and has the server flush; should that fail, the worker keeps serving.
    fn stop(
        &mut self,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<Option<Queue>, BlockIoError>;
    /// Have the worker look at the queue, as if the guest had notified it.
    fn kick(&self) -> Result<(), BlockIoError>;
    /// The rate limiter the worker uses, while it serves the queue.
    fn rate_limiter(&self) -> Option<&Arc<Mutex<RateLimiter>>>;
    /// Update the worker's rate limiter, or return the updates when it serves nothing.
    fn update_rate_limiter(
        &self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Option<(BucketUpdate, BucketUpdate)>;
}

impl QueueWorker for ThreadedFileEngine {
    fn is_serving(&self) -> bool {
        ThreadedFileEngine::is_serving(self)
    }
    fn start(
        &mut self,
        serving: threaded_io::Serving,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<(), BlockIoError> {
        ThreadedFileEngine::start(self, serving, device_rate_limiter)
            .map_err(BlockIoError::Threaded)
    }
    fn stop(
        &mut self,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<Option<Queue>, BlockIoError> {
        ThreadedFileEngine::stop(self, device_rate_limiter).map_err(BlockIoError::Threaded)
    }
    fn kick(&self) -> Result<(), BlockIoError> {
        ThreadedFileEngine::kick(self).map_err(BlockIoError::Threaded)
    }
    fn rate_limiter(&self) -> Option<&Arc<Mutex<RateLimiter>>> {
        ThreadedFileEngine::rate_limiter(self)
    }
    fn update_rate_limiter(
        &self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Option<(BucketUpdate, BucketUpdate)> {
        ThreadedFileEngine::update_rate_limiter(self, bytes, ops)
    }
}

impl QueueWorker for NbdFileEngine {
    fn is_serving(&self) -> bool {
        NbdFileEngine::is_serving(self)
    }
    fn start(
        &mut self,
        serving: threaded_io::Serving,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<(), BlockIoError> {
        NbdFileEngine::start(self, serving, device_rate_limiter).map_err(BlockIoError::Nbd)
    }
    fn stop(
        &mut self,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<Option<Queue>, BlockIoError> {
        NbdFileEngine::stop(self, device_rate_limiter).map_err(BlockIoError::Nbd)
    }
    fn kick(&self) -> Result<(), BlockIoError> {
        NbdFileEngine::kick(self).map_err(BlockIoError::Nbd)
    }
    fn rate_limiter(&self) -> Option<&Arc<Mutex<RateLimiter>>> {
        NbdFileEngine::rate_limiter(self)
    }
    fn update_rate_limiter(
        &self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Option<(BucketUpdate, BucketUpdate)> {
        NbdFileEngine::update_rate_limiter(self, bytes, ops)
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;

    use vm_memory::GuestMemoryRegion;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::utils::u64_to_usize;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::{Bitmap, Bytes, GuestMemory, GuestRegionMmapExt};

    const FILE_LEN: u32 = 1024;
    // 2 pages of memory should be enough to test read/write ops and also dirty tracking.
    const MEM_LEN: usize = 8192;

    macro_rules! assert_sync_execution {
        ($expression:expr, $count:expr) => {
            match $expression {
                Ok(FileEngineOk::Executed(RequestOk { req: _, count })) => {
                    assert_eq!(count, $count)
                }
                other => panic!(
                    "Expected: Ok(FileEngineOk::Executed(UserDataOk {{ user_data: _, count: {} \
                     }})), got: {:?}",
                    $count, other
                ),
            }
        };
    }

    macro_rules! assert_queued {
        ($expression:expr) => {
            assert!(matches!($expression, Ok(FileEngineOk::Submitted)))
        };
    }

    fn assert_async_execution(mem: &GuestMemoryMmap, engine: &mut FileEngine, count: u32) {
        if let FileEngine::Async(engine) = engine {
            engine.drain(false).unwrap();
            assert_eq!(engine.pop(mem).unwrap().unwrap().result().unwrap(), count);
        }
    }

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

    fn check_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert!(bitmap.dirty_at(u64_to_usize(offset)));
        }
    }

    fn check_clean_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32) {
        let bitmap = mem.find_region(addr).unwrap().bitmap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert!(!bitmap.dirty_at(u64_to_usize(offset)));
        }
    }

    #[test]
    fn test_sync() {
        let mem = create_mem();
        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync).unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - u64::from(partial_len));
        mem.write(&data, addr).unwrap();
        assert_sync_execution!(
            engine.write(0, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Partial read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(0, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Offset write
        let offset = 100;
        let partial_len = 50;
        let addr = GuestAddress(0);
        mem.write(&data, addr).unwrap();
        assert_sync_execution!(
            engine.write(offset, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Offset read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(offset, &mem, addr, partial_len, PendingRequest::default()),
            partial_len
        );
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_sync_execution!(
            engine.write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default()
            ),
            FILE_LEN
        );
        // Full read
        let mem = create_mem();
        assert_sync_execution!(
            engine.read(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default()
            ),
            FILE_LEN
        );
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());

        // Check other ops
        engine.flush(PendingRequest::default()).unwrap();
        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
    }

    #[test]
    fn test_async() {
        // Create backing file.
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Async).unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial reads and writes cannot really be tested because io_uring will return an error
        // code for trying to write to unmapped memory.

        // Offset write
        let mem = create_mem();
        let offset = 100;
        let partial_len = 50;
        let addr = GuestAddress(0);
        mem.write(&data, addr).unwrap();
        assert_queued!(engine.write(offset, &mem, addr, partial_len, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, partial_len);
        // Offset read
        let mem = create_mem();
        assert_queued!(engine.read(offset, &mem, addr, partial_len, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, partial_len);
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);
        // check dirty mem
        check_dirty_mem(&mem, addr, partial_len);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_queued!(engine.write(0, &mem, addr, FILE_LEN, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, FILE_LEN);

        // Full read
        let mem = create_mem();
        assert_queued!(engine.read(0, &mem, addr, FILE_LEN, PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, FILE_LEN);
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());
        // check dirty mem
        check_dirty_mem(&mem, addr, FILE_LEN);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Check other ops
        assert_queued!(engine.flush(PendingRequest::default()));
        assert_async_execution(&mem, &mut engine, 0);

        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
    }
}
