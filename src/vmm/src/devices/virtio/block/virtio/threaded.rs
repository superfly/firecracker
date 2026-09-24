// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Block device support for the threaded IO engine: handing the requests its worker thread
//! finished back to the guest.

use super::device::VirtioBlock;
use super::io::{BlockIoError, FileEngine};
use super::request::IoErr;
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::logger::{IncMetric, error};

impl VirtioBlock {
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
