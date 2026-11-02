// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A drive served over NBD under the default seccomp policy: the VMM thread under its "vmm"
//! filter, and the drive's worker under the "block_io" one, through requests, a snapshot's stop
//! and flush, the resume, and a reconnection after the server drops the connection.
//!
//! A forbidden call kills this test with SIGSYS, and a handler names it. The default policy is
//! written for musl, and only release builds compile it in, so this only runs in release builds
//! for musl targets.

#![allow(clippy::tests_outside_test_module)]
#![cfg(all(target_env = "musl", not(debug_assertions)))]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use vmm::devices::virtio::block::CacheType;
use vmm::devices::virtio::block::virtio::device::{FileEngineType, VirtioBlock, VirtioBlockConfig};
use vmm::devices::virtio::block::virtio::nbd::test_server::TestServer;
use vmm::devices::virtio::block::virtio::test_utils::set_queue;
use vmm::devices::virtio::block::virtio::{
    RequestHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, set_worker_seccomp_filter,
};
use vmm::devices::virtio::device::VirtioDevice;
use vmm::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use vmm::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
use vmm::seccomp::BpfProgram;
use vmm::vstate::memory::{Bytes, GuestAddress};

/// The `category` filter of the default seccomp policy, as compiled into this release build.
fn seccomp_filter(category: &str) -> BpfProgram {
    let bpf: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter.bpf"));
    let mut filters = vmm::seccomp::deserialize_binary(bpf).unwrap();
    Arc::into_inner(filters.remove(category).unwrap()).unwrap()
}

/// Report which system call a seccomp filter trapped, so that a failure names it.
extern "C" fn report_sigsys(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: the kernel passes a valid siginfo_t, and for SIGSYS its `_sigsys` member holds the
    // system call number at this offset on 64-bit Linux.
    let nr = unsafe { *info.cast::<u8>().add(24).cast::<libc::c_int>() };
    let mut msg = *b"seccomp trapped system call        \n";
    let mut n = u32::try_from(nr).unwrap_or(0);
    for i in (29..35).rev() {
        msg[i] = b'0' + u8::try_from(n % 10).unwrap();
        n /= 10;
    }
    // SAFETY: writing a local buffer to stderr, then exiting, both async-signal-safe.
    unsafe {
        libc::write(2, msg.as_ptr().cast(), msg.len());
        libc::_exit(1);
    }
}

fn wait_for(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        // Not sleep: the filter does not allow it.
        thread::yield_now();
    }
}

/// Put a request for the one-sector buffer at 0x2000 and `sector` in the queue, as its `n`th
/// request, and notify the device. Returns where its status goes.
fn request(
    block: &VirtioBlock,
    vq: &VirtQueue,
    n: u16,
    request_type: u32,
    sector: u64,
) -> GuestAddress {
    let (header, data, status) = (0x1000, 0x2000, 0x3000 + u64::from(n));
    let first = n * 3;
    vq.memory()
        .write_obj(
            RequestHeader::new(request_type, sector),
            GuestAddress(header),
        )
        .unwrap();
    let data_flags = match request_type {
        VIRTIO_BLK_T_IN => VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        _ => VIRTQ_DESC_F_NEXT,
    };
    vq.dtable[usize::from(first)].set(header, 16, VIRTQ_DESC_F_NEXT, first + 1);
    vq.dtable[usize::from(first + 1)].set(data, 512, data_flags, first + 2);
    vq.dtable[usize::from(first + 2)].set(status, 1, VIRTQ_DESC_F_WRITE, 0);
    vq.memory().write_obj(0xffu8, GuestAddress(status)).unwrap();
    vq.avail.ring[usize::from(n)].set(first);
    vq.avail.idx.set(n + 1);
    block.queue_evts[0].write(1).unwrap();
    GuestAddress(status)
}

#[test]
fn test_nbd_drive_under_seccomp() {
    let vmm_filter = seccomp_filter("vmm");
    set_worker_seccomp_filter(Arc::new(seccomp_filter("block_io")));
    // SAFETY: installing a handler that only calls async-signal-safe functions.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = report_sigsys as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut());
    }

    let server = TestServer::new(1 << 20);
    // Created before the VMM thread's filter, as drives are, before boot and on restore.
    let mut block = VirtioBlock::new(VirtioBlockConfig {
        drive_id: "nbd".to_string(),
        path_on_host: String::new(),
        is_root_device: false,
        partuuid: None,
        is_read_only: false,
        cache_type: CacheType::Writeback,
        rate_limiter: None,
        file_engine_type: FileEngineType::Nbd,
        nbd: Some(server.config()),
    })
    .unwrap();
    let mem = default_mem();
    let interrupt = default_interrupt();

    let state = server.state.clone();
    // The VMM thread may not close sockets: the test's main thread drops the connection for it.
    let (kill_tx, kill_rx) = std::sync::mpsc::channel::<()>();
    let (killed_tx, killed_rx) = std::sync::mpsc::channel::<()>();
    let vmm_thread = thread::spawn(move || {
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        mem.write_slice(&[0x5a; 512], GuestAddress(0x2000)).unwrap();
        vmm::seccomp::apply_filter(&vmm_filter).unwrap();

        // Activation, and the kick that hands the queue to the worker.
        block.activate(mem.clone(), interrupt).unwrap();
        block.process_virtio_queues().unwrap();
        let status = request(&block, &vq, 0, VIRTIO_BLK_T_OUT, 3);
        wait_for("the write", || vq.used.idx.get() == 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status).unwrap()),
            VIRTIO_BLK_S_OK
        );

        // A snapshot: the stop waits for what is in flight and has the server flush. Then the
        // kick on resume.
        block.quiesce().unwrap();
        block.prepare_save();
        assert_eq!(state.flushes.load(Ordering::SeqCst), 1);
        block.process_virtio_queues().unwrap();

        // The server drops the connection; the worker reconnects, under its own filter, and
        // serves a read on the new connection.
        kill_tx.send(()).unwrap();
        killed_rx.recv().unwrap();
        mem.write_slice(&[0u8; 512], GuestAddress(0x2000)).unwrap();
        let status = request(&block, &vq, 1, VIRTIO_BLK_T_IN, 3);
        wait_for("the read", || vq.used.idx.get() == 2);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status).unwrap()),
            VIRTIO_BLK_S_OK
        );
        let mut data = [0u8; 512];
        mem.read_slice(&mut data, GuestAddress(0x2000)).unwrap();
        assert_eq!(data, [0x5a; 512]);
        assert_eq!(state.connections.load(Ordering::SeqCst), 2);
        // The drive going away, with its worker.
        drop(block);
    });
    kill_rx.recv().unwrap();
    server.kill_connection();
    killed_tx.send(()).unwrap();
    vmm_thread.join().unwrap();
}
