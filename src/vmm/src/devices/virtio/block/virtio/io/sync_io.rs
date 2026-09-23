// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use vm_memory::{GuestMemoryError, ReadVolatile, WriteVolatile};

use super::{AlignedBuf, DirectIoError, direct_io_bounce};
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SyncIoError {
    /// Bounce buffer transfer: {0}
    Bounce(std::io::Error),
    /// Direct I/O: {0}
    DirectIo(DirectIoError),
    /// Flush: {0}
    Flush(std::io::Error),
    /// Seek: {0}
    Seek(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// Transfer: {0}
    Transfer(GuestMemoryError),
}

#[derive(Debug)]
pub struct SyncFileEngine {
    file: File,
    direct_align: Option<u32>,
}

// SAFETY: `File` is send and ultimately a POD.
unsafe impl Send for SyncFileEngine {}

impl SyncFileEngine {
    pub fn from_file(file: File, direct_align: Option<u32>) -> SyncFileEngine {
        SyncFileEngine { file, direct_align }
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File) {
        self.file = file
    }

    /// Returns a bounce buffer if a direct I/O request cannot use the guest buffer in place.
    fn direct_bounce(
        &self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<Option<AlignedBuf>, SyncIoError> {
        let Some(align) = self.direct_align else {
            return Ok(None);
        };
        let slice = mem
            .get_slice(addr, count as usize)
            .map_err(SyncIoError::Transfer)?;
        direct_io_bounce(align, offset, slice.ptr_guard().as_ptr() as usize, count)
            .map_err(SyncIoError::DirectIo)
    }

    pub fn read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        let bounce = self.direct_bounce(offset, mem, addr, count)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        if let Some(mut buf) = bounce {
            self.file
                .read_exact(buf.as_mut_slice())
                .map_err(SyncIoError::Bounce)?;
            mem.write_slice(buf.as_slice(), addr)
                .map_err(SyncIoError::Transfer)?;
            return Ok(count);
        }
        mem.get_slice(addr, count as usize)
            .and_then(|mut slice| Ok(self.file.read_exact_volatile(&mut slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
    ) -> Result<u32, SyncIoError> {
        let bounce = self.direct_bounce(offset, mem, addr, count)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(SyncIoError::Seek)?;
        if let Some(mut buf) = bounce {
            mem.read_slice(buf.as_mut_slice(), addr)
                .map_err(SyncIoError::Transfer)?;
            self.file
                .write_all(buf.as_slice())
                .map_err(SyncIoError::Bounce)?;
            return Ok(count);
        }
        mem.get_slice(addr, count as usize)
            .and_then(|slice| Ok(self.file.write_all_volatile(&slice)?))
            .map_err(SyncIoError::Transfer)?;
        Ok(count)
    }

    pub fn flush(&mut self) -> Result<(), SyncIoError> {
        // flush() first to force any cached data out of rust buffers.
        self.file.flush().map_err(SyncIoError::Flush)?;
        // Sync data out to physical media on host.
        self.file.sync_all().map_err(SyncIoError::SyncAll)
    }
}
