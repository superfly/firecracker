// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Everything the VMM thread does with a Threaded drive after boot, under its seccomp filter, and
//! the drive's worker serving it, under its own.
//!
//! The VMM thread runs under the "vmm" filter of the default policy once the microVM boots, and
//! each drive's worker under the "block_io" one, but unit tests never apply them, so a system call
//! a filter does not allow only shows in production. A forbidden call kills this test with SIGSYS,
//! and a handler names it.
//!
//! The default policy is written for musl, so this only runs on musl targets, which is where the
//! unit tests run in CI.

#![allow(clippy::tests_outside_test_module)]
#![cfg(target_env = "musl")]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vmm::devices::virtio::block::virtio::device::{FileEngineType, VirtioBlock};
use vmm::devices::virtio::block::virtio::test_utils::{default_block, set_queue};
use vmm::devices::virtio::block::virtio::{
    RequestHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_OUT, set_worker_seccomp_filter,
};
use vmm::devices::virtio::device::VirtioDevice;
use vmm::devices::virtio::generated::virtio_blk::{VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_T_DISCARD};
use vmm::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use vmm::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
use vmm::rate_limiter::{BucketUpdate, RateLimiter};
use vmm::seccomp::BpfProgram;
use vmm::vstate::memory::{Bytes, GuestAddress};
use vmm_sys_util::tempfile::TempFile;

/// A filter of the default seccomp policy for this target.
fn seccomp_filter(category: &str) -> BpfProgram {
    let json = format!(
        "{}/../../resources/seccomp/{}-unknown-linux-musl.json",
        env!("CARGO_MANIFEST_DIR"),
        std::env::consts::ARCH
    );
    let mut policy: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(json).unwrap()).unwrap();
    if cfg!(debug_assertions) {
        // Debug builds of the standard library check that a file descriptor is open before
        // closing it, with fcntl(F_GETFD). Release builds, which the policy is for, don't.
        policy[category]["filter"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "syscall": "fcntl",
                "args": [{"index": 1, "type": "dword", "op": "eq", "val": libc::F_GETFD}]
            }));
    }
    let json = TempFile::new().unwrap();
    std::fs::write(json.as_path(), policy.to_string()).unwrap();
    let bpf = TempFile::new().unwrap();
    seccompiler::compile_bpf(
        json.as_path().to_str().unwrap(),
        std::env::consts::ARCH,
        bpf.as_path().to_str().unwrap(),
        false,
        false,
    )
    .unwrap();
    let mut filters = vmm::seccomp::deserialize_binary(bpf.into_file()).unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        // Not sleep: the filter does not allow it.
        thread::yield_now();
    }
}

/// Put a write of the one-sector buffer at 0x2000 to `sector` in the queue, as its `n`th
/// request, and notify the device. Returns where its status goes.
fn write_request(block: &VirtioBlock, vq: &VirtQueue, n: u16, sector: u64) -> GuestAddress {
    let (header, data, status) = (0x1000, 0x2000, 0x3000 + u64::from(n));
    let first = n * 3;
    vq.memory()
        .write_obj(
            RequestHeader::new(VIRTIO_BLK_T_OUT, sector),
            GuestAddress(header),
        )
        .unwrap();
    vq.dtable[usize::from(first)].set(header, 16, VIRTQ_DESC_F_NEXT, first + 1);
    vq.dtable[usize::from(first + 1)].set(data, 512, VIRTQ_DESC_F_NEXT, first + 2);
    vq.dtable[usize::from(first + 2)].set(status, 1, VIRTQ_DESC_F_WRITE, 0);
    vq.memory().write_obj(0xffu8, GuestAddress(status)).unwrap();
    vq.avail.ring[usize::from(n)].set(first);
    vq.avail.idx.set(n + 1);
    block.queue_evts[0].write(1).unwrap();
    GuestAddress(status)
}

/// Put a discard of `num_sectors` sectors from `sector` in the queue, as its `n`th request, and
/// notify the device.
fn discard_request(block: &VirtioBlock, vq: &VirtQueue, n: u16, sector: u64, num_sectors: u32) {
    let (header, range, status) = (0x1000, 0x2800, 0x3000 + u64::from(n));
    let first = n * 3;
    vq.memory()
        .write_obj(
            RequestHeader::new(VIRTIO_BLK_T_DISCARD, 0),
            GuestAddress(header),
        )
        .unwrap();
    // struct virtio_blk_discard_write_zeroes: sector, num_sectors, flags.
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&sector.to_le_bytes());
    bytes[8..12].copy_from_slice(&num_sectors.to_le_bytes());
    vq.memory()
        .write_slice(&bytes, GuestAddress(range))
        .unwrap();
    vq.dtable[usize::from(first)].set(header, 16, VIRTQ_DESC_F_NEXT, first + 1);
    vq.dtable[usize::from(first + 1)].set(range, 16, VIRTQ_DESC_F_NEXT, first + 2);
    vq.dtable[usize::from(first + 2)].set(status, 1, VIRTQ_DESC_F_WRITE, 0);
    vq.avail.ring[usize::from(n)].set(first);
    vq.avail.idx.set(n + 1);
    block.queue_evts[0].write(1).unwrap();
}

#[test]
fn test_threaded_drive_under_vmm_seccomp() {
    let filter = seccomp_filter("vmm");
    // Workers apply it when they start, which is when their drive is created.
    set_worker_seccomp_filter(Arc::new(seccomp_filter("block_io")));
    // SAFETY: installing a handler that only calls async-signal-safe functions.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = report_sigsys as usize;
        action.sa_flags = libc::SA_SIGINFO;
        libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut());
    }

    // Created before the filter, as drives are, before boot.
    let mut block = default_block(FileEngineType::Threaded);
    block.rate_limiter = RateLimiter::new(0, 0, 0, 1000, 0, 1000);
    block.acked_features |= 1 << VIRTIO_BLK_F_DISCARD;
    let mem = default_mem();
    let interrupt = default_interrupt();
    let new_file = TempFile::new().unwrap();
    new_file.as_file().set_len(0x2000).unwrap();
    let new_path = new_file.as_path().to_str().unwrap().to_string();

    thread::spawn(move || {
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        mem.write_slice(&[0x5a; 512], GuestAddress(0x2000)).unwrap();
        vmm::seccomp::apply_filter(&filter).unwrap();

        // Activation, and the kick that hands the queue to the worker.
        block.activate(mem.clone(), interrupt).unwrap();
        block.process_virtio_queues().unwrap();

        // PATCH /drives, to a file twice the size, then a write past the end of the old one. The
        // worker duplicates the new file.
        block.update_disk_image(new_path).unwrap();
        assert_eq!(block.config_space.capacity, 16);
        let status = write_request(&block, &vq, 0, 12);
        wait_for("the write", || vq.used.idx.get() == 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status).unwrap()),
            VIRTIO_BLK_S_OK
        );

        // PATCH /drives with a rate limiter, and GET /vm/config.
        block.update_rate_limiter(BucketUpdate::None, BucketUpdate::Disabled);
        assert!(block.config().rate_limiter.is_none());

        // A snapshot, then the kick on resume, which has the worker serve the queue again.
        block.prepare_save();
        block.process_virtio_queues().unwrap();
        let status = write_request(&block, &vq, 1, 13);
        wait_for("the write after resume", || vq.used.idx.get() == 2);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status).unwrap()),
            VIRTIO_BLK_S_OK
        );

        // A discard: the worker checks what the file is, then punches a hole in it. Whether it
        // can depends on the host's filesystem, so only the completion counts.
        discard_request(&block, &vq, 2, 4, 2);
        wait_for("the discard", || vq.used.idx.get() == 3);

        // The drive going away.
        drop(block);
    })
    .join()
    .unwrap();
}
