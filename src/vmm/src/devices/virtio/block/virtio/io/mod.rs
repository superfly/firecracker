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

/// Largest request copied through an aligned buffer when its guest buffer is not aligned for
/// direct I/O. Larger unaligned requests fail rather than allocate host memory for the guest.
pub const MAX_DIRECT_IO_BOUNCE_LEN: u32 = 1 << 20;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DirectIoError {
    /// Offset {0} and length {1} must be multiples of the {2}-byte direct I/O block size
    Unaligned(u64, u32, u32),
    /// Unaligned guest buffer of {0} bytes exceeds the {1}-byte bounce buffer limit
    BounceTooLarge(u32, u32),
}

/// Heap buffer whose contents start at an address aligned for direct I/O.
#[derive(Debug)]
pub struct AlignedBuf {
    buf: Vec<u8>,
    start: usize,
    len: usize,
}

impl AlignedBuf {
    fn new(len: u32, align: u32) -> Self {
        let (len, align) = (len as usize, align as usize);
        let buf = vec![0; len + align];
        // The allocation does not move with the Vec, so the aligned start stays valid.
        let addr = buf.as_ptr() as usize;
        let start = addr.next_multiple_of(align) - addr;
        Self { buf, start, len }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.start..self.start + self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.start + self.len]
    }
}

/// Checks a direct I/O request against the backing file's `align`ment.
///
/// Offsets and lengths must already be aligned. A guest buffer at an unaligned `host_addr` is
/// served through the returned bounce buffer; `None` means the guest buffer can be used in place.
pub fn direct_io_bounce(
    align: u32,
    offset: u64,
    host_addr: usize,
    count: u32,
) -> Result<Option<AlignedBuf>, DirectIoError> {
    if offset % u64::from(align) != 0 || count % align != 0 {
        return Err(DirectIoError::Unaligned(offset, count, align));
    }
    if host_addr % align as usize == 0 {
        return Ok(None);
    }
    if count > MAX_DIRECT_IO_BOUNCE_LEN {
        return Err(DirectIoError::BounceTooLarge(
            count,
            MAX_DIRECT_IO_BOUNCE_LEN,
        ));
    }
    Ok(Some(AlignedBuf::new(count, align)))
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FileEngine {
    #[allow(unused)]
    Async(AsyncFileEngine),
    Sync(SyncFileEngine),
}

impl FileEngine {
    /// Creates an engine for `file`. `direct_align` is set when the file was opened with
    /// `O_DIRECT`, and gives the alignment its offsets, lengths and buffers require.
    pub fn from_file(
        file: File,
        engine_type: FileEngineType,
        direct_align: Option<u32>,
    ) -> Result<FileEngine, BlockIoError> {
        match engine_type {
            FileEngineType::Async => Ok(FileEngine::Async(
                AsyncFileEngine::from_file(file, direct_align).map_err(BlockIoError::Async)?,
            )),
            FileEngineType::Sync => Ok(FileEngine::Sync(SyncFileEngine::from_file(
                file,
                direct_align,
            ))),
        }
    }

    pub fn file(&self) -> &File {
        match self {
            FileEngine::Async(engine) => engine.file(),
            FileEngine::Sync(engine) => engine.file(),
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
        }
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), BlockIoError> {
        match self {
            FileEngine::Async(engine) => {
                engine.drain_and_flush(discard).map_err(BlockIoError::Async)
            }
            FileEngine::Sync(engine) => engine.flush().map_err(BlockIoError::Sync),
        }
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
        let mut engine = FileEngine::from_file(file, FileEngineType::Sync, None).unwrap();

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
        let mut engine = FileEngine::from_file(file, FileEngineType::Async, None).unwrap();

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

    #[test]
    fn test_direct_io_bounce() {
        // Aligned offset, length and buffer are used in place.
        assert!(
            direct_io_bounce(4096, 8192, 0x10000, 4096)
                .unwrap()
                .is_none()
        );

        // Offsets and lengths must be block multiples.
        for (offset, count) in [(512, 4096), (4096, 512), (4096, 0x1200)] {
            assert!(matches!(
                direct_io_bounce(4096, offset, 0x10000, count),
                Err(DirectIoError::Unaligned(o, c, 4096)) if o == offset && c == count
            ));
        }

        // An unaligned buffer gets an aligned bounce buffer of the request's length.
        let buf = direct_io_bounce(4096, 0, 0x10200, 8192).unwrap().unwrap();
        assert_eq!(buf.as_slice().len(), 8192);
        assert_eq!(buf.as_slice().as_ptr() as usize % 4096, 0);

        // Bounce buffers are bounded.
        let too_large = MAX_DIRECT_IO_BOUNCE_LEN + 4096;
        assert!(matches!(
            direct_io_bounce(4096, 0, 0x10200, too_large),
            Err(DirectIoError::BounceTooLarge(c, MAX_DIRECT_IO_BOUNCE_LEN)) if c == too_large
        ));
        assert!(
            direct_io_bounce(4096, 0, 0x10000, too_large)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn test_direct_io_engines() {
        const BLOCK: u32 = 4096;
        let data = vmm_sys_util::rand::rand_alphanumerics(BLOCK as usize)
            .as_bytes()
            .to_vec();
        // Guest memory is page aligned, so these addresses are aligned and unaligned for 4 KiB.
        let aligned = GuestAddress(0);
        let unaligned_write = GuestAddress(512);
        let unaligned_read = GuestAddress(1024);

        for engine_type in [FileEngineType::Sync, FileEngineType::Async] {
            let file = TempFile::new().unwrap().into_file();
            file.set_len(2 * u64::from(BLOCK)).unwrap();
            let mut engine = FileEngine::from_file(file, engine_type, Some(BLOCK)).unwrap();

            let run =
                |engine: &mut FileEngine,
                 mem: &GuestMemoryMmap,
                 res: Result<FileEngineOk, RequestError<BlockIoError>>| {
                    match engine_type {
                        FileEngineType::Sync => assert_sync_execution!(res, BLOCK),
                        FileEngineType::Async => {
                            assert_queued!(res);
                            assert_async_execution(mem, engine, BLOCK);
                        }
                    }
                };

            // Write from an unaligned guest buffer, through a bounce buffer.
            let mem = create_mem();
            mem.write(&data, unaligned_write).unwrap();
            let res = engine.write(
                u64::from(BLOCK),
                &mem,
                unaligned_write,
                BLOCK,
                PendingRequest::default(),
            );
            run(&mut engine, &mem, res);

            // Read into an unaligned guest buffer, through a bounce buffer.
            let mem = create_mem();
            let res = engine.read(
                u64::from(BLOCK),
                &mem,
                unaligned_read,
                BLOCK,
                PendingRequest::default(),
            );
            run(&mut engine, &mem, res);
            let mut buf = vec![0u8; BLOCK as usize];
            mem.read_slice(&mut buf, unaligned_read).unwrap();
            assert_eq!(buf, data);
            check_dirty_mem(&mem, unaligned_read, BLOCK);

            // Read into an aligned guest buffer, in place.
            let mem = create_mem();
            let res = engine.read(
                u64::from(BLOCK),
                &mem,
                aligned,
                BLOCK,
                PendingRequest::default(),
            );
            run(&mut engine, &mem, res);
            mem.read_slice(&mut buf, aligned).unwrap();
            assert_eq!(buf, data);

            // Unaligned offsets and lengths are rejected without touching the file.
            for (offset, count) in [(512, BLOCK), (0, 512)] {
                let res = engine.write(offset, &mem, aligned, count, PendingRequest::default());
                let err = res.map(|_| ()).unwrap_err().error;
                assert!(
                    matches!(
                        err,
                        BlockIoError::Sync(SyncIoError::DirectIo(DirectIoError::Unaligned(..)))
                            | BlockIoError::Async(AsyncIoError::DirectIo(
                                DirectIoError::Unaligned(..)
                            ))
                    ),
                    "{err:?}"
                );
            }
        }
    }
}
