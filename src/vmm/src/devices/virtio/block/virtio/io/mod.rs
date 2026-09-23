// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod async_io;
pub mod sync_io;

use std::fmt::Debug;
use std::fs::File;

pub use self::async_io::{AsyncFileEngine, AsyncIoError};
pub use self::sync_io::{SyncFileEngine, SyncIoError};
use crate::devices::virtio::block::virtio::PendingRequest;
use crate::devices::virtio::block::virtio::device::FileEngineType;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

#[derive(Debug)]
pub enum FileEngineOk {
    Submitted,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockIoError {
    /// Sync error: {0}
    Sync(SyncIoError),
    /// Async error: {0}
    Async(AsyncIoError),
}

impl BlockIoError {
    pub fn is_throttling_err(&self) -> bool {
        match self {
            BlockIoError::Async(AsyncIoError::IoUring(err)) => err.is_throttling_err(),
            BlockIoError::Sync(SyncIoError::QueueFull) => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct RequestError<E> {
    pub req: PendingRequest,
    pub error: E,
}

impl<E> RequestError<E> {
    fn map<F>(self, f: impl FnOnce(E) -> F) -> RequestError<F> {
        RequestError {
            req: self.req,
            error: f(self.error),
        }
    }
}

/// A request the engine finished, with its outcome.
#[derive(Debug)]
pub struct Completion {
    pub req: PendingRequest,
    pub result: Result<u32, BlockIoError>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FileEngine {
    #[allow(unused)]
    Async(AsyncFileEngine),
    Sync(SyncFileEngine),
}

impl FileEngine {
    pub fn from_file(file: File, engine_type: FileEngineType) -> Result<FileEngine, BlockIoError> {
        match engine_type {
            FileEngineType::Async => Ok(FileEngine::Async(
                AsyncFileEngine::from_file(file).map_err(BlockIoError::Async)?,
            )),
            FileEngineType::Sync => Ok(FileEngine::Sync(
                SyncFileEngine::from_file(file).map_err(BlockIoError::Sync)?,
            )),
        }
    }

    pub fn update_file_path(&mut self, file: File) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine.update_file(file).map_err(BlockIoError::Async)?,
            FileEngine::Sync(engine) => engine.update_file(file).map_err(BlockIoError::Sync)?,
        };

        Ok(())
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        match self {
            FileEngine::Async(engine) => engine.file(),
            FileEngine::Sync(engine) => engine.file(),
        }
    }

    /// The eventfd signalled when submitted requests complete.
    pub fn completion_evt(&self) -> &EventFd {
        match self {
            FileEngine::Async(engine) => engine.completion_evt(),
            FileEngine::Sync(engine) => engine.completion_evt(),
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
            FileEngine::Async(engine) => engine
                .push_read(offset, mem, addr, count, req)
                .map_err(|err| err.map(BlockIoError::Async)),
            FileEngine::Sync(engine) => engine
                .push_read(offset, mem, addr, count, req)
                .map_err(|err| err.map(BlockIoError::Sync)),
        }
        .map(|_| FileEngineOk::Submitted)
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
            FileEngine::Async(engine) => engine
                .push_write(offset, mem, addr, count, req)
                .map_err(|err| err.map(BlockIoError::Async)),
            FileEngine::Sync(engine) => engine
                .push_write(offset, mem, addr, count, req)
                .map_err(|err| err.map(BlockIoError::Sync)),
        }
        .map(|_| FileEngineOk::Submitted)
    }

    pub fn flush(
        &mut self,
        req: PendingRequest,
    ) -> Result<FileEngineOk, RequestError<BlockIoError>> {
        match self {
            FileEngine::Async(engine) => engine
                .push_flush(req)
                .map_err(|err| err.map(BlockIoError::Async)),
            FileEngine::Sync(engine) => engine
                .push_flush(req)
                .map_err(|err| err.map(BlockIoError::Sync)),
        }
        .map(|_| FileEngineOk::Submitted)
    }

    /// Pop a finished request, if there is one.
    pub fn pop(&mut self, mem: &GuestMemoryMmap) -> Result<Option<Completion>, BlockIoError> {
        match self {
            FileEngine::Async(engine) => {
                let cqe = engine.pop(mem).map_err(BlockIoError::Async)?;
                Ok(cqe.map(|cqe| {
                    let result = cqe
                        .result()
                        .map_err(|err| BlockIoError::Async(AsyncIoError::IO(err)));
                    Completion {
                        req: cqe.user_data(),
                        result,
                    }
                }))
            }
            FileEngine::Sync(engine) => Ok(engine.pop().map(|completion| Completion {
                req: completion.req,
                result: completion.result.map_err(BlockIoError::Sync),
            })),
        }
    }

    pub fn drain(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => engine.drain(discard).map_err(BlockIoError::Async),
            FileEngine::Sync(engine) => engine.drain(discard).map_err(BlockIoError::Sync),
        }
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => {
                engine.drain_and_flush(discard).map_err(BlockIoError::Async)
            }
            FileEngine::Sync(engine) => engine.drain_and_flush(discard).map_err(BlockIoError::Sync),
        }
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

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

    macro_rules! assert_queued {
        ($expression:expr) => {
            assert!(matches!($expression, Ok(FileEngineOk::Submitted)))
        };
    }

    fn assert_execution(mem: &GuestMemoryMmap, engine: &mut FileEngine, count: u32) {
        engine.drain(false).unwrap();
        let completion = engine.pop(mem).unwrap().unwrap();
        assert_eq!(completion.result.unwrap(), count);
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
        assert_queued!(engine.write(0, &mem, addr, partial_len, PendingRequest::default()));
        assert_execution(&mem, &mut engine, partial_len);
        // Partial read
        let mem = create_mem();
        assert_queued!(engine.read(0, &mem, addr, partial_len, PendingRequest::default()));
        assert_execution(&mem, &mut engine, partial_len);
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Offset write
        let offset = 100;
        let partial_len = 50;
        let addr = GuestAddress(0);
        mem.write(&data, addr).unwrap();
        assert_queued!(engine.write(offset, &mem, addr, partial_len, PendingRequest::default()));
        assert_execution(&mem, &mut engine, partial_len);
        // Offset read
        let mem = create_mem();
        assert_queued!(engine.read(offset, &mem, addr, partial_len, PendingRequest::default()));
        assert_execution(&mem, &mut engine, partial_len);
        // Check data
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);
        // check dirty mem
        check_dirty_mem(&mem, addr, partial_len);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Full write
        mem.write(&data, GuestAddress(0)).unwrap();
        assert_queued!(engine.write(
            0,
            &mem,
            GuestAddress(0),
            FILE_LEN,
            PendingRequest::default()
        ));
        assert_execution(&mem, &mut engine, FILE_LEN);
        // Full read
        let mem = create_mem();
        assert_queued!(engine.read(
            0,
            &mem,
            GuestAddress(0),
            FILE_LEN,
            PendingRequest::default()
        ));
        assert_execution(&mem, &mut engine, FILE_LEN);
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());
        // check dirty mem
        check_dirty_mem(&mem, GuestAddress(0), FILE_LEN);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Out of bounds guest memory fails the request, not the engine.
        assert_queued!(engine.read(
            0,
            &mem,
            GuestAddress(MEM_LEN as u64),
            FILE_LEN,
            PendingRequest::default()
        ));
        engine.drain(false).unwrap();
        let completion = engine.pop(&mem).unwrap().unwrap();
        assert!(matches!(
            completion.result,
            Err(BlockIoError::Sync(SyncIoError::Transfer(_)))
        ));

        // Check other ops
        assert_queued!(engine.flush(PendingRequest::default()));
        assert_execution(&mem, &mut engine, 0);

        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
    }

    #[test]
    fn test_sync_runs_off_thread() {
        let mem = create_mem();
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync).unwrap();

        // Submitting returns before the IO is done: completions only show up through the
        // completion eventfd, once the worker has finished them.
        for _ in 0..10 {
            assert_queued!(engine.write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default()
            ));
        }
        let mut completed = 0;
        while completed < 10 {
            // Blocks until the worker signals; the eventfd is non-blocking, so poll it.
            match engine.completion_evt().read() {
                Ok(_) => {
                    while let Some(completion) = engine.pop(&mem).unwrap() {
                        assert_eq!(completion.result.unwrap(), FILE_LEN);
                        completed += 1;
                    }
                }
                Err(err) => {
                    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
                    std::thread::yield_now();
                }
            }
        }
        assert!(engine.pop(&mem).unwrap().is_none());
    }

    #[test]
    fn test_sync_throttling() {
        let mem = create_mem();
        let file = TempFile::new().unwrap().into_file();
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync).unwrap();

        for _ in 0..sync_io::SYNC_IO_MAX_IN_FLIGHT {
            assert_queued!(engine.flush(PendingRequest::default()));
        }
        // Completed but not yet popped requests still count as in flight.
        engine.drain(false).unwrap();
        let err = engine.flush(PendingRequest::default()).unwrap_err();
        assert!(err.error.is_throttling_err());

        // Popping a completion makes room for one more request.
        engine.pop(&mem).unwrap().unwrap();
        assert_queued!(engine.flush(PendingRequest::default()));
        let err = engine.flush(PendingRequest::default()).unwrap_err();
        assert!(err.error.is_throttling_err());

        // Discarding all completions makes room for all of them.
        engine.drain(true).unwrap();
        assert!(engine.pop(&mem).unwrap().is_none());
        for _ in 0..sync_io::SYNC_IO_MAX_IN_FLIGHT {
            assert_queued!(engine.flush(PendingRequest::default()));
        }
        engine.drain(true).unwrap();
    }

    #[test]
    fn test_sync_update_file() {
        let mem = create_mem();
        let old = TempFile::new().unwrap();
        let new = TempFile::new().unwrap();
        let mut engine =
            FileEngine::from_file(old.as_file().try_clone().unwrap(), FileEngineType::Sync)
                .unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();
        mem.write(&data, GuestAddress(0)).unwrap();

        // Requests submitted before the update go to the old file, the ones after to the new one,
        // without waiting for the first to complete.
        assert_queued!(engine.write(
            0,
            &mem,
            GuestAddress(0),
            FILE_LEN,
            PendingRequest::default()
        ));
        engine
            .update_file_path(new.as_file().try_clone().unwrap())
            .unwrap();
        assert_queued!(engine.write(0, &mem, GuestAddress(0), 10, PendingRequest::default()));
        engine.drain(true).unwrap();

        assert_eq!(old.as_file().metadata().unwrap().len(), u64::from(FILE_LEN));
        assert_eq!(new.as_file().metadata().unwrap().len(), 10);
        assert_eq!(
            engine.file().metadata().unwrap().ino(),
            new.as_file().metadata().unwrap().ino()
        );
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
        assert_execution(&mem, &mut engine, partial_len);
        // Offset read
        let mem = create_mem();
        assert_queued!(engine.read(offset, &mem, addr, partial_len, PendingRequest::default()));
        assert_execution(&mem, &mut engine, partial_len);
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
        assert_execution(&mem, &mut engine, FILE_LEN);

        // Full read
        let mem = create_mem();
        assert_queued!(engine.read(0, &mem, addr, FILE_LEN, PendingRequest::default()));
        assert_execution(&mem, &mut engine, FILE_LEN);
        // Check data
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data.as_slice());
        // check dirty mem
        check_dirty_mem(&mem, addr, FILE_LEN);
        check_clean_mem(&mem, GuestAddress(4096), 4096);

        // Check other ops
        assert_queued!(engine.flush(PendingRequest::default()));
        assert_execution(&mem, &mut engine, 0);

        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
    }
}
