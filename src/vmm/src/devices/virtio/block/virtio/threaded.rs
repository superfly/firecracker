// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Block device support for the threaded IO engine: requests with several data buffers, and
//! handing the queue to the engine's worker thread, which serves it from activation on.

use vm_memory::ByteValued;

use std::os::unix::io::AsRawFd;

use super::device::{FileEngineType, VirtioBlock};
use super::io::FileEngine;
use super::io::threaded_io::{Serving, THREADED_SEG_MAX};
use super::request::{Request, RequestType};
use super::{SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError};
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_SEG_MAX;
use crate::devices::virtio::queue::DescriptorChain;
use crate::logger::{IncMetric, error};
use crate::rate_limiter::BucketUpdate;
use crate::utils::u64_to_usize;
use crate::vmm_config::RateLimiterConfig;
use crate::vstate::memory::GuestMemoryMmap;

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

    /// Hand the queue to the worker, which serves it from then on. Called once the device is
    /// activated, and again after `threaded_stop`, when the device is kicked.
    pub(super) fn threaded_start(&mut self) {
        let FileEngine::Threaded(engine) = &self.disk.file_engine else {
            return;
        };
        if engine.is_serving() {
            return;
        }
        let Some(active_state) = self.device_state.active_state() else {
            return;
        };
        let serving = Serving {
            // The device keeps its copy for the transport, which reads the queue's
            // configuration. The worker's copy is the one in use until it hands it back.
            queue: self.queues[0].clone(),
            queue_evt: self.queue_evts[0].as_raw_fd(),
            mem: active_state.mem.clone(),
            interrupt: active_state.interrupt.clone(),
            metrics: self.metrics.clone(),
            nsectors: self.disk.nsectors,
            image_id: self.disk.image_id,
            segmented: self.accepts_segments(),
            drive_id: self.id.clone(),
        };
        let FileEngine::Threaded(engine) = &mut self.disk.file_engine else {
            return;
        };
        if let Err(err) = engine.start(serving, &mut self.rate_limiter) {
            error!("Failed to start the block IO worker: {:?}", err);
            self.metrics.event_fails.inc();
        }
    }

    /// Take the queue and the rate limiter back from the worker, for the device to save them,
    /// or before it goes away.
    pub(super) fn threaded_stop(&mut self) {
        let FileEngine::Threaded(engine) = &mut self.disk.file_engine else {
            return;
        };
        match engine.stop(&mut self.rate_limiter) {
            Ok(Some(queue)) => self.queues[0] = queue,
            Ok(None) => {}
            Err(err) => error!("Failed to stop the block IO worker: {:?}", err),
        }
    }

    /// Have the worker look at the queue, starting it if it is not serving. Returns false if the
    /// device does not use the threaded engine.
    pub(super) fn threaded_kick(&mut self) -> bool {
        let FileEngine::Threaded(engine) = &self.disk.file_engine else {
            return false;
        };
        if !engine.is_serving() {
            // Starting serves what is queued.
            self.threaded_start();
        } else if let Err(err) = engine.kick() {
            error!("Failed to kick the block IO worker: {:?}", err);
        }
        true
    }

    /// The configuration of the rate limiter the worker uses, while it serves the queue.
    pub(super) fn threaded_rate_limiter_config(&self) -> Option<RateLimiterConfig> {
        let FileEngine::Threaded(engine) = &self.disk.file_engine else {
            return None;
        };
        let rate_limiter = engine.rate_limiter()?;
        let rate_limiter = rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock");
        Some((&*rate_limiter).into())
    }

    /// Update the rate limiter the worker uses, while it serves the queue. Returns the updates
    /// back otherwise.
    pub(super) fn threaded_update_rate_limiter(
        &self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Option<(BucketUpdate, BucketUpdate)> {
        match &self.disk.file_engine {
            FileEngine::Threaded(engine) => engine.update_rate_limiter(bytes, ops),
            _ => Some((bytes, ops)),
        }
    }

    /// Switch the worker to the backing file the disk was just updated with.
    pub(super) fn threaded_disk_updated(&mut self) {
        let (nsectors, image_id) = (self.disk.nsectors, self.disk.image_id);
        if let FileEngine::Threaded(engine) = &mut self.disk.file_engine
            && let Err(err) = engine.update_disk(nsectors, image_id)
        {
            error!("Failed to update the block IO worker's disk: {:?}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use event_manager::{EventManager, SubscriberOps};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::persist::BlockConstructorArgs;
    use crate::devices::virtio::block::virtio::device::VirtioBlockConfig;
    use crate::devices::virtio::block::virtio::test_utils::{default_block, set_queue};
    use crate::devices::virtio::block::virtio::{
        CacheType, RequestHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_IN,
        VIRTIO_BLK_T_OUT,
    };
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::devices::virtio::transport::VirtioInterruptType;
    use crate::rate_limiter::RateLimiter;
    use crate::snapshot::Persist;
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

    fn wait_for(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn engine(
        block: &VirtioBlock,
    ) -> &crate::devices::virtio::block::virtio::io::ThreadedFileEngine {
        match &block.disk.file_engine {
            FileEngine::Threaded(engine) => engine,
            _ => panic!("not a threaded block device"),
        }
    }

    /// Activate the device and hand its queue to the worker, as the event loop does.
    fn serve(block: &mut VirtioBlock, mem: &GuestMemoryMmap) {
        block.activate(mem.clone(), default_interrupt()).unwrap();
        block.threaded_start();
        assert!(engine(block).is_serving());
    }

    fn notify(block: &VirtioBlock) {
        block.queue_evts[0].write(1).unwrap();
    }

    fn interrupted(block: &VirtioBlock) -> bool {
        block
            .interrupt_trigger()
            .has_pending_interrupt(VirtioInterruptType::Queue(0))
    }

    #[test]
    fn test_engine_type() {
        let block = default_block(FileEngineType::Threaded);
        assert!(matches!(block.disk.file_engine, FileEngine::Threaded(_)));
        assert_eq!(block.file_engine_type(), FileEngineType::Threaded);
        assert_eq!(block.config().file_engine_type, FileEngineType::Threaded);
    }

    /// Chain a header, `segments` data buffers and a status, from descriptor 0 on.
    fn set_request(
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
    fn test_read_write() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        serve(&mut block, &mem);

        // The backing file is 8 sectors. Write 4 of them from three scattered buffers.
        let data: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        mem.write_slice(&data[..512], GuestAddress(0x4000)).unwrap();
        mem.write_slice(&data[512..1536], GuestAddress(0x2000))
            .unwrap();
        mem.write_slice(&data[1536..], GuestAddress(0x6000))
            .unwrap();
        let status_addr = set_request(
            &vq,
            VIRTIO_BLK_T_OUT,
            2,
            &[(0x4000, 512), (0x2000, 1024), (0x6000, 512)],
        );
        // The worker serves the queue from the guest's notification, without the event loop.
        notify(&block);
        wait_for("the write", || vq.used.idx.get() == 1);
        wait_for("the interrupt", || interrupted(&block));
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );

        // Read them back as two buffers.
        let status_addr = set_request(&vq, VIRTIO_BLK_T_IN, 2, &[(0x8000, 1536), (0xa000, 512)]);
        vq.avail.ring[1].set(0);
        vq.avail.idx.set(2);
        vq.used.idx.set(1);
        notify(&block);
        wait_for("the read", || vq.used.idx.get() == 2);
        assert_eq!(vq.used.ring[1].get().len, 2049);
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
    fn test_serves_what_was_queued_before() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        add_flush_requests_batch(&mut block, &vq, 5);
        // No notification: the worker looks at the queue when it starts.
        serve(&mut block, &mem);
        wait_for("the flushes", || vq.used.idx.get() == 5);
        check_flush_requests_batch(5, &vq);
    }

    #[test]
    fn test_rate_limiter() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        add_flush_requests_batch(&mut block, &vq, 4);
        // One op per 100 ms.
        block.rate_limiter = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
        serve(&mut block, &mem);

        wait_for("the first flush", || vq.used.idx.get() >= 1);
        // The worker has the rate limiter, and the device reports it.
        let config = block.config().rate_limiter.unwrap();
        assert_eq!(config.ops.unwrap().size, 1);
        // Its timer lets the rest through, one at a time.
        wait_for("the second flush", || vq.used.idx.get() >= 2);

        // An update reaches the worker's rate limiter.
        block.update_rate_limiter(BucketUpdate::None, BucketUpdate::Disabled);
        assert!(block.config().rate_limiter.is_none());
        block.process_virtio_queues().unwrap();
        wait_for("the other flushes", || vq.used.idx.get() == 4);
        check_flush_requests_batch(4, &vq);
    }

    #[test]
    fn test_prepare_save() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        add_flush_requests_batch(&mut block, &vq, 5);
        block.rate_limiter = RateLimiter::new(0, 0, 0, 100, 0, 1000).unwrap();
        serve(&mut block, &mem);
        wait_for("the flushes", || vq.used.idx.get() == 5);

        // The device gets the queue, as the worker left it, and its rate limiter back.
        block.prepare_save();
        assert!(!engine(&block).is_serving());
        assert_eq!(block.queues[0].next_avail.0, 5);
        assert_eq!(block.queues[0].next_used.0, 5);
        let config: RateLimiterConfig = (&block.rate_limiter).into();
        assert_eq!(config.ops.unwrap().size, 100);

        // A kick, as when the VM resumes, has the worker serve the queue again.
        block.process_virtio_queues().unwrap();
        assert!(engine(&block).is_serving());
    }

    #[test]
    fn test_update_disk_image() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        serve(&mut block, &mem);

        // A new backing file of 16 sectors, twice the old one.
        let new_file = TempFile::new().unwrap();
        new_file.as_file().set_len(0x2000).unwrap();
        block
            .update_disk_image(new_file.as_path().to_str().unwrap().to_string())
            .unwrap();
        assert_eq!(block.config_space.capacity, 16);

        // The worker writes to it, past the end of the old one.
        mem.write_slice(&[0x5a; 512], GuestAddress(0x2000)).unwrap();
        let status_addr = set_request(&vq, VIRTIO_BLK_T_OUT, 12, &[(0x2000, 512)]);
        notify(&block);
        wait_for("the write", || vq.used.idx.get() == 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );
        let mut buf = [0u8; 512];
        use std::os::unix::fs::FileExt;
        new_file
            .as_file()
            .read_exact_at(&mut buf, 12 * 512)
            .unwrap();
        assert_eq!(buf, [0x5a; 512]);
    }

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let block = Arc::new(Mutex::new(block));
        set_queue(&mut block.lock().unwrap(), 0, vq.create_queue());
        event_manager.add_subscriber(block.clone());
        block
            .lock()
            .unwrap()
            .activate(mem.clone(), default_interrupt())
            .unwrap();
        // The activation event hands the queue to the worker.
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);
        assert!(engine(&block.lock().unwrap()).is_serving());

        // Which serves the queue from then on: the event loop gets no event for it.
        let status_addr = set_request(&vq, VIRTIO_BLK_T_OUT, 0, &[(0x2000, 512)]);
        notify(&block.lock().unwrap());
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 0);
        wait_for("the write", || vq.used.idx.get() == 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );
    }

    #[test]
    fn test_worker_thread_name() {
        let mut block = default_block(FileEngineType::Threaded);
        block.id = "vol_x7k2p9q4mz81".to_string();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        serve(&mut block, &mem);

        // The prefix and the drive id, cut to the 15 bytes Linux keeps.
        let names = || {
            std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|task| std::fs::read_to_string(task.unwrap().path().join("comm")).ok())
                .map(|name| name.trim_end().to_string())
                .collect::<Vec<_>>()
        };
        wait_for("the worker's name", || {
            names().contains(&"blk_vol_x7k2p9q".to_string())
        });
    }

    #[test]
    fn test_drop_while_serving() {
        let mut block = default_block(FileEngineType::Threaded);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        add_flush_requests_batch(&mut block, &vq, 4);
        // Leave requests waiting on the rate limiter.
        block.rate_limiter = RateLimiter::new(0, 0, 0, 1, 0, 10_000).unwrap();
        serve(&mut block, &mem);
        wait_for("the first flush", || vq.used.idx.get() == 1);
        drop(block);
    }

    #[test]
    fn test_segmented_parse_failures() {
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 64);
        let parse = |request_type, sector, segments: &[(u64, u32)]| {
            set_request(&vq, request_type, sector, segments);
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
        set_request(&vq, VIRTIO_BLK_T_IN, 0, &[(0x2000, 512), (0x3000, 512)]);
        vq.dtable[2].flags.set(VIRTQ_DESC_F_NEXT);
        let mut queue = vq.create_queue();
        let head = queue.pop().unwrap().unwrap();
        assert!(matches!(
            Request::parse_segmented(&head, &mem, 8),
            Err(VirtioBlockError::UnexpectedReadOnlyDescriptor)
        ));
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
        crate::snapshot::Snapshot::new(block.save())
            .save(&mut snapshot.as_mut_slice())
            .unwrap();
        let restored = VirtioBlock::restore(
            BlockConstructorArgs { mem: default_mem() },
            &crate::snapshot::Snapshot::load_without_crc_check(snapshot.as_slice())
                .unwrap()
                .data,
        )
        .unwrap();

        assert_eq!(restored.file_engine_type(), FileEngineType::Threaded);
        assert!(matches!(restored.disk.file_engine, FileEngine::Threaded(_)));
    }
}
