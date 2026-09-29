// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Block device support for the threaded IO engine: handing the requests its worker thread
//! finished back to the guest.

use vm_memory::ByteValued;

use super::device::{DiskProperties, FileEngineType, VirtioBlock};
use super::io::threaded_io::THREADED_SEG_MAX;
use super::io::{BlockIoError, FileEngine};
use super::metrics::BlockDeviceMetrics;
use super::request::{IoErr, ProcessingResult, Request, RequestType};
use super::{SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError};
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_SEG_MAX;
use crate::devices::virtio::queue::DescriptorChain;
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::logger::{IncMetric, error};
use crate::utils::u64_to_usize;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

/// The start of `struct virtio_blk_config`, up to `seg_max`. The device's own config space ends
/// after `capacity`.
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct SegmentedConfigSpace {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
}

// SAFETY: `SegmentedConfigSpace` contains only PODs in `repr(C)`, without padding.
unsafe impl ByteValued for SegmentedConfigSpace {}

impl Request {
    /// Parse a request, with any number of data buffers if `segmented`.
    pub fn parse_any(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
        num_disk_sectors: u64,
        segmented: bool,
    ) -> Result<Request, VirtioBlockError> {
        if segmented {
            Self::parse_segmented(avail_desc, mem, num_disk_sectors)
        } else {
            Self::parse(avail_desc, mem, num_disk_sectors)
        }
    }

    /// Parse a request whose data may come in several buffers: every descriptor between the
    /// header and the status is one. Requests that are not reads or writes are left to `parse`.
    pub fn parse_segmented(
        avail_desc: &DescriptorChain,
        mem: &GuestMemoryMmap,
        num_disk_sectors: u64,
    ) -> Result<Request, VirtioBlockError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(VirtioBlockError::UnexpectedWriteOnlyDescriptor);
        }
        let header: super::RequestHeader = {
            use crate::vstate::memory::Bytes;
            mem.read_obj(avail_desc.addr)
                .map_err(VirtioBlockError::GuestMemory)?
        };
        let (r#type, sector) = header.type_and_sector();
        if r#type != RequestType::In && r#type != RequestType::Out {
            return Self::parse(avail_desc, mem, num_disk_sectors);
        }

        let mut segments = Vec::new();
        let mut data_len: u32 = 0;
        let mut desc = avail_desc
            .next_descriptor()
            .ok_or(VirtioBlockError::DescriptorChainTooShort)?;
        // The last descriptor is the status, the ones before it are data.
        while let Some(next) = desc.next_descriptor() {
            // This also bounds the walk, should the chain loop.
            if segments.len() >= u64_to_usize(u64::from(THREADED_SEG_MAX)) {
                return Err(VirtioBlockError::TooManySegments);
            }
            if desc.is_write_only() && r#type == RequestType::Out {
                return Err(VirtioBlockError::UnexpectedWriteOnlyDescriptor);
            }
            if !desc.is_write_only() && r#type == RequestType::In {
                return Err(VirtioBlockError::UnexpectedReadOnlyDescriptor);
            }
            data_len = data_len
                .checked_add(desc.len)
                .ok_or(VirtioBlockError::InvalidDataLength)?;
            segments.push((desc.addr, desc.len));
            desc = next;
        }
        let status_desc = desc;
        if segments.is_empty() {
            return Err(VirtioBlockError::DescriptorChainTooShort);
        }

        // Check that the data length is a multiple of 512 as specified in the virtio standard.
        if data_len % SECTOR_SIZE != 0 {
            return Err(VirtioBlockError::InvalidDataLength);
        }
        let top_sector = sector
            .checked_add(u64::from(data_len) >> SECTOR_SHIFT)
            .ok_or(VirtioBlockError::InvalidOffset)?;
        if top_sector > num_disk_sectors {
            return Err(VirtioBlockError::InvalidOffset);
        }

        // The status MUST always be writable.
        if !status_desc.is_write_only() {
            return Err(VirtioBlockError::UnexpectedReadOnlyDescriptor);
        }
        if status_desc.len < 1 {
            return Err(VirtioBlockError::DescriptorLengthTooSmall);
        }

        Ok(Request {
            r#type,
            data_len,
            status_addr: status_desc.addr,
            sector,
            data_addr: segments[0].0,
            segments,
        })
    }

    /// Submit a read or write parsed by `parse_segmented` to the threaded engine.
    pub(super) fn process_segmented(
        self,
        disk: &mut DiskProperties,
        desc_idx: u16,
        mem: &GuestMemoryMmap,
        block_metrics: &BlockDeviceMetrics,
    ) -> ProcessingResult {
        let pending = self.to_pending_request(desc_idx);
        let offset = self.sector << SECTOR_SHIFT;
        let FileEngine::Threaded(engine) = &mut disk.file_engine else {
            // Only the threaded engine has requests parsed that way.
            return ProcessingResult::Executed(pending.finish(
                mem,
                Err(IoErr::PartialTransfer {
                    completed: 0,
                    expected: self.data_len,
                }),
                block_metrics,
            ));
        };

        let res = match self.r#type {
            RequestType::In => engine.push_readv(offset, mem, self.segments, pending),
            _ => engine.push_writev(offset, mem, self.segments, pending),
        };
        match res {
            Ok(()) => ProcessingResult::Submitted,
            Err(err) => {
                let error = BlockIoError::Threaded(err.error);
                if error.is_throttling_err() {
                    ProcessingResult::Throttled
                } else {
                    ProcessingResult::Executed(err.req.finish(
                        mem,
                        Err(IoErr::FileEngine(error)),
                        block_metrics,
                    ))
                }
            }
        }
    }
}

impl VirtioBlock {
    /// Features only the threaded engine offers.
    pub(super) fn threaded_features(engine_type: FileEngineType) -> u64 {
        match engine_type {
            FileEngineType::Threaded => 1u64 << VIRTIO_BLK_F_SEG_MAX,
            _ => 0,
        }
    }

    /// Whether requests may have several data buffers. Decided by what the device offered, not
    /// by what the driver accepted: a driver that did not accept it sends one buffer anyway.
    pub(super) fn accepts_segments(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_SEG_MAX) != 0
            && matches!(self.disk.file_engine, FileEngine::Threaded(_))
    }

    /// Serve a config space read from the longer config space of a device that takes several
    /// data buffers per request. Returns false if this device does not.
    pub(super) fn threaded_read_config(&self, offset: u64, data: &mut [u8]) -> bool {
        if !self.accepts_segments() {
            return false;
        }

        let config_space = SegmentedConfigSpace {
            capacity: self.config_space.capacity,
            size_max: 0,
            seg_max: THREADED_SEG_MAX.to_le(),
        };
        if let Some(bytes) = config_space.as_slice().get(u64_to_usize(offset)..) {
            let len = bytes.len().min(data.len());
            data[..len].copy_from_slice(&bytes[..len]);
        } else {
            error!("Failed to read config space");
            self.metrics.cfg_fails.inc();
        }
        true
    }

    /// Handle the threaded engine's completion eventfd.
    pub(crate) fn process_threaded_completion_event(&mut self) {
        let FileEngine::Threaded(engine) = &self.disk.file_engine else {
            error!("The block device doesn't use a threaded IO engine");
            return;
        };

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get threaded completion event: {:?}", err);
            return;
        }
        self.process_threaded_completion_queue();

        if self.is_io_engine_throttled {
            self.is_io_engine_throttled = false;
            self.process_queue(0).unwrap()
        }
    }

    /// Hand the requests of a pass over the queue to the worker and, while the backing file is
    /// fast, wait for them and complete them right away.
    pub(crate) fn threaded_kick(&mut self) {
        let FileEngine::Threaded(engine) = &mut self.disk.file_engine else {
            return;
        };
        // A throttled device resumes its queue from the completion event.
        let completed = if self.is_io_engine_throttled {
            engine.kick().map(|_| false)
        } else {
            engine.kick_and_poll()
        };
        match completed {
            Ok(true) => self.process_threaded_completion_queue(),
            Ok(false) => {}
            Err(err) => error!("BlockError submitting pending block requests: {:?}", err),
        }
    }

    /// Add every request the worker finished to the used ring, and notify the guest.
    pub(crate) fn process_threaded_completion_queue(&mut self) {
        let FileEngine::Threaded(engine) = &mut self.disk.file_engine else {
            return;
        };

        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();
        let queue = &mut self.queues[0];

        while let Some(completion) = engine.pop() {
            let res = completion
                .result
                .map_err(|err| IoErr::FileEngine(BlockIoError::Threaded(err)));
            let finished = completion.req.finish(&active_state.mem, res, &self.metrics);
            queue
                .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                .unwrap_or_else(|err| {
                    error!(
                        "Failed to add available descriptor head {}: {}",
                        finished.desc_idx, err
                    )
                });
        }
        queue.advance_used_ring_idx();

        if queue.prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }
    }
}

/// Wait for the threaded engine to finish everything submitted, then handle its completion event
/// and check whether the guest got an interrupt.
#[cfg(test)]
pub fn simulate_threaded_completion_event(b: &mut VirtioBlock, expected_irq: bool) {
    use crate::devices::virtio::device::VirtioDevice;

    b.disk.file_engine.drain(false).unwrap();
    b.process_threaded_completion_event();
    assert_eq!(
        b.interrupt_trigger()
            .has_pending_interrupt(VirtioInterruptType::Queue(0)),
        expected_irq
    );
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use event_manager::{EventManager, SubscriberOps};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::persist::BlockConstructorArgs;
    use crate::devices::virtio::block::virtio::device::{FileEngineType, VirtioBlockConfig};
    use crate::devices::virtio::block::virtio::io::threaded_io::THREADED_IO_MAX_IN_FLIGHT;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, read_blk_req_descriptors, set_queue, simulate_queue_event,
    };
    use crate::devices::virtio::block::virtio::{
        CacheType, RequestHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN,
        VIRTIO_BLK_T_OUT,
    };
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::snapshot::{Persist, Snapshot};
    use crate::vstate::memory::{Address, Bytes, GuestAddress};

    fn add_flush_requests_batch(block: &mut VirtioBlock, vq: &VirtQueue, count: u16) {
        let mem = vq.memory();
        vq.avail.idx.set(0);
        vq.used.idx.set(0);
        set_queue(block, 0, vq.create_queue());

        let hdr_addr = vq
            .end()
            .checked_align_up(std::mem::align_of::<RequestHeader>() as u64)
            .unwrap();
        mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_FLUSH, 0), hdr_addr)
            .unwrap();
        let mut status_addr = hdr_addr
            .checked_add(std::mem::size_of::<RequestHeader>() as u64)
            .unwrap()
            .checked_align_up(4)
            .unwrap();

        for i in 0..count {
            let idx = i * 2;
            let hdr_desc = &vq.dtable[idx as usize];
            hdr_desc.addr.set(hdr_addr.0);
            hdr_desc.flags.set(VIRTQ_DESC_F_NEXT);
            hdr_desc.next.set(idx + 1);

            let status_desc = &vq.dtable[idx as usize + 1];
            status_desc.addr.set(status_addr.0);
            status_desc.flags.set(VIRTQ_DESC_F_WRITE);
            status_desc.len.set(4);
            status_addr = status_addr.checked_add(4).unwrap();

            vq.avail.ring[i as usize].set(idx);
            vq.avail.idx.set(i + 1);
        }
    }

    fn check_flush_requests_batch(count: u16, vq: &VirtQueue) {
        assert_eq!(vq.used.idx.get(), count);
        for i in 0..count {
            let used = vq.used.ring[i as usize].get();
            let status_addr = vq.dtable[used.id as usize + 1].addr.get();
            assert_eq!(used.len, 1);
            assert_eq!(
                u32::from(
                    vq.memory()
                        .read_obj::<u8>(GuestAddress(status_addr))
                        .unwrap()
                ),
                VIRTIO_BLK_S_OK
            );
        }
    }

    #[test]
    fn test_engine_type() {
        let block = default_block(FileEngineType::Threaded);
        assert!(matches!(block.disk.file_engine, FileEngine::Threaded(_)));
        assert_eq!(block.file_engine_type(), FileEngineType::Threaded);
        assert_eq!(block.config().file_engine_type, FileEngineType::Threaded);
    }

    #[test]
    fn test_read_write() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();
        read_blk_req_descriptors(&vq);

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Write.
        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
            .unwrap();
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(512);
        mem.write_obj::<u64>(123_456_789, data_addr).unwrap();
        // Submitting does not complete the request...
        simulate_queue_event(&mut block, Some(false));
        assert_eq!(vq.used.idx.get(), 0);
        // ...the worker's completion does.
        simulate_threaded_completion_event(&mut block, true);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

        // Read it back.
        vq.used.idx.set(0);
        set_queue(&mut block, 0, vq.create_queue());
        mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
            .unwrap();
        vq.dtable[1]
            .flags
            .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
        mem.write_obj::<u64>(0, data_addr).unwrap();
        simulate_queue_event(&mut block, Some(false));
        simulate_threaded_completion_event(&mut block, true);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().len, 513);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        assert_eq!(mem.read_obj::<u64>(data_addr).unwrap(), 123_456_789);
    }

    /// Chain a header, `segments` data buffers and a status, from descriptor 0 on.
    fn set_segmented_request(
        vq: &VirtQueue,
        request_type: u32,
        sector: u64,
        segments: &[(u64, u32)],
    ) -> GuestAddress {
        let (header_addr, status_addr) = (0x1000, 0x1800);
        vq.memory()
            .write_obj(
                RequestHeader::new(request_type, sector),
                GuestAddress(header_addr),
            )
            .unwrap();
        vq.dtable[0].set(header_addr, 16, VIRTQ_DESC_F_NEXT, 1);
        let data_flags = match request_type {
            VIRTIO_BLK_T_IN => VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            _ => VIRTQ_DESC_F_NEXT,
        };
        let mut idx = 1;
        for &(addr, len) in segments {
            vq.dtable[usize::from(idx)].set(addr, len, data_flags, idx + 1);
            idx += 1;
        }
        vq.dtable[usize::from(idx)].set(status_addr, 1, VIRTQ_DESC_F_WRITE, 0);
        vq.memory()
            .write_obj(0xffu8, GuestAddress(status_addr))
            .unwrap();
        vq.avail.ring[0].set(0);
        vq.avail.idx.set(1);
        vq.used.idx.set(0);
        GuestAddress(status_addr)
    }

    #[test]
    fn test_features_and_config_space() {
        let block = default_block(FileEngineType::Threaded);
        assert_ne!(block.avail_features() & (1 << VIRTIO_BLK_F_SEG_MAX), 0);
        assert!(block.accepts_segments());

        // capacity (8 sectors), size_max, seg_max
        let mut config = [0xffu8; 16];
        block.read_config(0, &mut config);
        assert_eq!(config[..8], 8u64.to_le_bytes());
        assert_eq!(config[8..12], 0u32.to_le_bytes());
        assert_eq!(config[12..], THREADED_SEG_MAX.to_le_bytes());
        // Partial reads, as the guest does them.
        let mut seg_max = [0u8; 4];
        block.read_config(12, &mut seg_max);
        assert_eq!(seg_max, THREADED_SEG_MAX.to_le_bytes());

        // The other engines offer neither the feature nor the longer config space.
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let block = default_block(engine);
            assert_eq!(block.avail_features() & (1 << VIRTIO_BLK_F_SEG_MAX), 0);
            assert!(!block.accepts_segments());
            let mut config = [0xffu8; 16];
            block.read_config(0, &mut config);
            assert_eq!(config[..8], 8u64.to_le_bytes());
            assert_eq!(config[8..], [0xff; 8]);
        }
    }

    #[test]
    fn test_segmented_read_write() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();

        // The backing file is 8 sectors. Write 4 of them from three scattered buffers.
        let data: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        mem.write_slice(&data[..512], GuestAddress(0x4000)).unwrap();
        mem.write_slice(&data[512..1536], GuestAddress(0x2000))
            .unwrap();
        mem.write_slice(&data[1536..], GuestAddress(0x6000))
            .unwrap();
        let status_addr = set_segmented_request(
            &vq,
            VIRTIO_BLK_T_OUT,
            2,
            &[(0x4000, 512), (0x2000, 1024), (0x6000, 512)],
        );
        simulate_queue_event(&mut block, Some(false));
        simulate_threaded_completion_event(&mut block, true);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );

        // Read them back as two buffers.
        set_queue(&mut block, 0, vq.create_queue());
        let status_addr =
            set_segmented_request(&vq, VIRTIO_BLK_T_IN, 2, &[(0x8000, 1536), (0xa000, 512)]);
        simulate_queue_event(&mut block, Some(false));
        simulate_threaded_completion_event(&mut block, true);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().len, 2049);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );
        let mut buf = vec![0u8; 2048];
        mem.read_slice(&mut buf[..1536], GuestAddress(0x8000))
            .unwrap();
        mem.read_slice(&mut buf[1536..], GuestAddress(0xa000))
            .unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_segmented_parse_failures() {
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 64);
        let parse = |request_type, sector, segments: &[(u64, u32)]| {
            set_segmented_request(&vq, request_type, sector, segments);
            let mut queue = vq.create_queue();
            let head = queue.pop().unwrap().unwrap();
            Request::parse_segmented(&head, &mem, 8)
        };

        // As many buffers as advertised, but no more.
        let max = usize::try_from(THREADED_SEG_MAX).unwrap();
        let segments: Vec<(u64, u32)> = (0..=max).map(|i| (0x2000 + 512 * i as u64, 0)).collect();
        let request = parse(VIRTIO_BLK_T_OUT, 0, &segments[..max]).unwrap();
        assert_eq!(request.segments.len(), max);
        assert!(matches!(
            parse(VIRTIO_BLK_T_OUT, 0, &segments),
            Err(VirtioBlockError::TooManySegments)
        ));

        // The total length counts: a multiple of the sector size, within the disk.
        parse(VIRTIO_BLK_T_OUT, 0, &[(0x2000, 256), (0x3000, 256)]).unwrap();
        assert!(matches!(
            parse(VIRTIO_BLK_T_OUT, 0, &[(0x2000, 512), (0x3000, 256)]),
            Err(VirtioBlockError::InvalidDataLength)
        ));
        assert!(matches!(
            parse(VIRTIO_BLK_T_OUT, 6, &[(0x2000, 512), (0x3000, 1024)]),
            Err(VirtioBlockError::InvalidOffset)
        ));
        assert!(matches!(
            parse(VIRTIO_BLK_T_OUT, 0, &[(0x2000, u32::MAX), (0x3000, 512)]),
            Err(VirtioBlockError::InvalidDataLength)
        ));
        // No data at all.
        assert!(matches!(
            parse(VIRTIO_BLK_T_IN, 0, &[]),
            Err(VirtioBlockError::DescriptorChainTooShort)
        ));

        // Every buffer has to have the direction of the request.
        set_segmented_request(&vq, VIRTIO_BLK_T_IN, 0, &[(0x2000, 512), (0x3000, 512)]);
        vq.dtable[2].flags.set(VIRTQ_DESC_F_NEXT);
        let mut queue = vq.create_queue();
        let head = queue.pop().unwrap().unwrap();
        assert!(matches!(
            Request::parse_segmented(&head, &mem, 8),
            Err(VirtioBlockError::UnexpectedReadOnlyDescriptor)
        ));
    }

    #[test]
    fn test_completed_in_the_queue_event() {
        let mut block = default_block(FileEngineType::Threaded);
        let FileEngine::Threaded(engine) = &mut block.disk.file_engine else {
            unreachable!()
        };
        engine.set_poll_budget(Some(std::time::Duration::from_secs(10)));
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();

        // The write is submitted, completed and notified in one queue event.
        mem.write_obj::<u64>(123_456_789, GuestAddress(0x2000))
            .unwrap();
        let status_addr = set_segmented_request(&vq, VIRTIO_BLK_T_OUT, 0, &[(0x2000, 512)]);
        simulate_queue_event(&mut block, Some(true));
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );
        // The completion event has nothing left to do.
        let FileEngine::Threaded(engine) = &mut block.disk.file_engine else {
            unreachable!()
        };
        engine.completion_evt().read().unwrap_err();
        assert!(engine.pop().is_none());
    }

    #[test]
    fn test_throttling() {
        let limit = u16::try_from(THREADED_IO_MAX_IN_FLIGHT).unwrap();
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, limit * 4);
        block.queues[0] = vq.create_queue();
        block.activate(mem.clone(), default_interrupt()).unwrap();

        // Up to the limit, everything is submitted.
        add_flush_requests_batch(&mut block, &vq, limit);
        simulate_queue_event(&mut block, Some(false));
        assert!(!block.is_io_engine_throttled);
        simulate_threaded_completion_event(&mut block, true);
        check_flush_requests_batch(limit, &vq);

        // Beyond it, the device stops until completions come back, then resumes the queue.
        add_flush_requests_batch(&mut block, &vq, limit + 10);
        simulate_queue_event(&mut block, Some(false));
        assert!(block.is_io_engine_throttled);
        simulate_threaded_completion_event(&mut block, true);
        assert!(!block.is_io_engine_throttled);
        check_flush_requests_batch(limit, &vq);
        simulate_threaded_completion_event(&mut block, true);
        assert!(!block.is_io_engine_throttled);
        check_flush_requests_batch(limit + 10, &vq);
    }

    #[test]
    fn test_prepare_save() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        block.queues[0] = vq.create_queue();
        block.activate(mem.clone(), default_interrupt()).unwrap();

        add_flush_requests_batch(&mut block, &vq, 5);
        simulate_queue_event(&mut block, None);
        block.prepare_save();

        // Every request submitted to the worker was finished and handed back to the guest.
        check_flush_requests_batch(5, &vq);
    }

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        read_blk_req_descriptors(&vq);
        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, GuestAddress(vq.dtable[0].addr.get()))
            .unwrap();
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(512);

        let block = Arc::new(Mutex::new(block));
        event_manager.add_subscriber(block.clone());
        block
            .lock()
            .unwrap()
            .activate(mem.clone(), default_interrupt())
            .unwrap();
        // Process the activate event.
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);

        // The queue event submits the request, and the completion event, registered by the
        // device, finishes it.
        block.lock().unwrap().queue_evts[0].write(1).unwrap();
        for _ in 0..10 {
            event_manager.run_with_timeout(100).unwrap();
            if vq.used.idx.get() == 1 {
                break;
            }
        }
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(
            mem.read_obj::<u32>(GuestAddress(vq.dtable[2].addr.get()))
                .unwrap(),
            VIRTIO_BLK_S_OK
        );
    }

    #[test]
    fn test_persistence() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let block = VirtioBlock::new(VirtioBlockConfig {
            drive_id: "threaded".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::Threaded,
        })
        .unwrap();

        let mut snapshot = vec![0; 4096];
        Snapshot::new(block.save())
            .save(&mut snapshot.as_mut_slice())
            .unwrap();
        let restored = VirtioBlock::restore(
            BlockConstructorArgs { mem: default_mem() },
            &Snapshot::load_without_crc_check(snapshot.as_slice())
                .unwrap()
                .data,
        )
        .unwrap();

        assert_eq!(restored.file_engine_type(), FileEngineType::Threaded);
        assert!(matches!(restored.disk.file_engine, FileEngine::Threaded(_)));
    }
}
