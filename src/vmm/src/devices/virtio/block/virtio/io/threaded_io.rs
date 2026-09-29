// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Threaded file engine.
//!
//! Blocking I/O, like the sync engine, but not on the thread that submits it: each engine owns a
//! worker thread that performs the requests one at a time, in submission order, and reports
//! completions through an eventfd, the way the async engine does. A slow backing file then stalls
//! only its own worker, not the event loop and every other device serviced there, and no
//! io_uring support is needed.
//!
//! Requests are vectored: one request carries up to [`THREADED_SEG_MAX`] guest buffers and is
//! served by a single `preadv`/`pwritev`. They are handed to the worker in batches, one per
//! [`ThreadedFileEngine::kick`], so that a pass over the virtqueue wakes the worker once.
//!
//! While the backing file is fast, the submitter waits for the completions right after the kick,
//! for up to [`POLL_BUDGET`], see [`ThreadedFileEngine::kick_and_poll`]. A request is then submitted and
//! completed in one wake-up of the event loop, as with the sync engine, where the eventfd would
//! take a second one.

use std::collections::VecDeque;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use vm_memory::GuestMemoryError;
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::block::virtio::PendingRequest;
use crate::devices::virtio::block::virtio::io::RequestError;
use crate::logger::error;
use crate::seccomp::{BpfProgram, BpfProgramRef};
use crate::vstate::memory::{GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap};

/// Maximum number of requests submitted to the worker and not yet popped. The engine reports
/// itself as throttled beyond this, and the device resumes processing its queue once completions
/// come back.
pub const THREADED_IO_MAX_IN_FLIGHT: usize = 128;

/// Maximum number of data buffers in one request, advertised to the guest as `seg_max`.
///
/// Without it a guest must send one request per physically contiguous buffer, which for page
/// cache writeback means one per 4 KiB page. Indirect descriptors are not supported, so a
/// request takes this many entries of the 256-entry queue, plus two.
pub const THREADED_SEG_MAX: u32 = 32;

/// How long the submitter waits for completions after a kick, at most. This is time the event
/// loop serves nothing else, so it has to stay far below what any other device would notice.
pub const POLL_BUDGET: Duration = Duration::from_micros(100);

/// How many requests may be in flight for the submitter to wait for them. Waiting pays when a
/// guest sends a request and does nothing until it completes. With more in flight, completions
/// are handled in bursts anyway, and the wait would only take time from the event loop.
pub const POLL_MAX_IN_FLIGHT: usize = 2;

/// A guest buffer: its address and length.
pub type Segment = (GuestAddress, u32);

/// How long a finished request may wait for the requests queued behind it before the device is
/// told about it.
const COMPLETION_SIGNAL_DELAY: Duration = Duration::from_micros(200);

/// Filter the worker threads apply to themselves, see [`set_worker_seccomp_filter`].
static WORKER_SECCOMP_FILTER: OnceLock<Arc<BpfProgram>> = OnceLock::new();

/// Set the seccomp filter each worker thread applies to itself when it starts.
///
/// Workers are started whenever a drive is created, which is before the VMM thread installs its
/// own filter, so they cannot rely on inheriting it. Only the first call has an effect.
pub fn set_worker_seccomp_filter(filter: Arc<BpfProgram>) {
    // Ignoring the error is what makes later calls no-ops.
    let _ = WORKER_SECCOMP_FILTER.set(filter);
}

fn worker_seccomp_filter() -> Option<BpfProgramRef<'static>> {
    WORKER_SECCOMP_FILTER.get().map(|filter| filter.as_slice())
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ThreadedIoError {
    /// Read: {0}
    Read(std::io::Error),
    /// Write: {0}
    Write(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// Guest memory: {0}
    GuestMemory(GuestMemoryError),
    /// EventFd: {0}
    EventFd(std::io::Error),
    /// Cloning the backing file: {0}
    FileClone(std::io::Error),
    /// Spawning the IO worker thread: {0}
    Spawn(std::io::Error),
    /// Too many requests in flight
    QueueFull,
    /// The IO worker thread is gone
    WorkerGone,
}

/// What the submitter tells the worker about the completions it needs no signal for.
#[derive(Debug, Default)]
struct Received {
    // Set while the submitter is polling for completions.
    polling: AtomicBool,
    // How many completions the submitter has received so far.
    count: AtomicU64,
}

/// A finished request, as reported by the worker thread.
#[derive(Debug)]
pub struct ThreadedCompletion {
    pub req: PendingRequest,
    pub result: Result<u32, ThreadedIoError>,
}

#[derive(Debug)]
enum Io {
    Read {
        offset: u64,
        mem: GuestMemoryMmap,
        segments: Vec<Segment>,
    },
    Write {
        offset: u64,
        mem: GuestMemoryMmap,
        segments: Vec<Segment>,
    },
    Flush,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
}

/// Transfer `segments` from or to `file` at `offset` with positioned, vectored IO: one system
/// call, unless the kernel transfers less than asked.
fn transfer(
    file: &File,
    direction: Direction,
    mut offset: u64,
    mem: &GuestMemoryMmap,
    segments: &[Segment],
) -> Result<u32, ThreadedIoError> {
    let mut iovecs = Vec::with_capacity(segments.len());
    let mut total: u32 = 0;
    for &(addr, len) in segments {
        let slice = mem
            .get_slice(addr, len as usize)
            .map_err(ThreadedIoError::GuestMemory)?;
        iovecs.push(libc::iovec {
            iov_base: slice.ptr_guard_mut().as_ptr().cast(),
            iov_len: len as usize,
        });
        total = total.checked_add(len).ok_or(ThreadedIoError::GuestMemory(
            GuestMemoryError::GuestAddressOverflow,
        ))?;
    }

    let io_error = |err| match direction {
        Direction::Read => ThreadedIoError::Read(err),
        Direction::Write => ThreadedIoError::Write(err),
    };

    let mut iovecs = iovecs.as_mut_slice();
    while !iovecs.is_empty() {
        let iovcnt = libc::c_int::try_from(iovecs.len()).unwrap_or(libc::c_int::MAX);
        let offset_arg =
            libc::off_t::try_from(offset).map_err(|_| io_error(libc::EOVERFLOW.into_io()))?;
        // SAFETY: the iovecs point into guest memory that `mem`, which outlives the call, keeps
        // mapped, each within the bounds `get_slice` checked.
        let ret = unsafe {
            match direction {
                Direction::Read => {
                    libc::preadv(file.as_raw_fd(), iovecs.as_ptr(), iovcnt, offset_arg)
                }
                Direction::Write => {
                    libc::pwritev(file.as_raw_fd(), iovecs.as_ptr(), iovcnt, offset_arg)
                }
            }
        };
        let mut done = match usize::try_from(ret) {
            Ok(0) => {
                return Err(io_error(match direction {
                    Direction::Read => std::io::ErrorKind::UnexpectedEof.into(),
                    Direction::Write => std::io::ErrorKind::WriteZero.into(),
                }));
            }
            Ok(done) => done,
            Err(_) => {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(io_error(err));
            }
        };
        offset += done as u64;

        // Skip what was transferred: whole buffers first, then the start of the next one.
        while let Some(first) = iovecs.first_mut() {
            if done < first.iov_len {
                // SAFETY: `done` is within the buffer.
                first.iov_base = unsafe { first.iov_base.add(done) };
                first.iov_len -= done;
                break;
            }
            done -= first.iov_len;
            iovecs = &mut iovecs[1..];
        }
    }

    Ok(total)
}

trait IntoIoError {
    fn into_io(self) -> std::io::Error;
}

impl IntoIoError for libc::c_int {
    fn into_io(self) -> std::io::Error {
        std::io::Error::from_raw_os_error(self)
    }
}

impl Io {
    fn execute(self, file: &File) -> Result<u32, ThreadedIoError> {
        match self {
            Io::Read {
                offset,
                mem,
                segments,
            } => {
                let count = transfer(file, Direction::Read, offset, &mem, &segments)?;
                // The guest memory was written from this thread, so account for it in the dirty
                // bitmap before the device gets to see the completion.
                for (addr, len) in segments {
                    mem.mark_dirty(addr, len as usize);
                }
                Ok(count)
            }
            Io::Write {
                offset,
                mem,
                segments,
            } => transfer(file, Direction::Write, offset, &mem, &segments),
            // Sync data out to physical media on host.
            Io::Flush => file.sync_all().map(|_| 0).map_err(ThreadedIoError::SyncAll),
        }
    }
}

#[derive(Debug)]
enum Op {
    Io {
        io: Io,
        req: PendingRequest,
    },
    /// Switch to a new backing file. Requests submitted before it use the old one.
    UpdateFile(File),
    /// Acknowledged once every request submitted before it has completed.
    Barrier(mpsc::SyncSender<()>),
    Exit,
}

/// Coalesces the completion eventfd writes of the worker thread.
#[derive(Debug)]
struct CompletionSignal {
    evt: EventFd,
    pending: bool,
    last: Instant,
    // How many completions were sent so far.
    sent: u64,
    received: Arc<Received>,
}

impl CompletionSignal {
    fn new(evt: EventFd, received: Arc<Received>) -> Self {
        CompletionSignal {
            evt,
            pending: false,
            last: Instant::now(),
            sent: 0,
            received,
        }
    }

    /// Signal pending completions if the last signal is old enough.
    fn maybe_flush(&mut self) {
        if self.last.elapsed() >= COMPLETION_SIGNAL_DELAY {
            self.flush();
        }
    }

    /// Signal pending completions.
    fn flush(&mut self) {
        if !self.pending {
            return;
        }
        self.pending = false;
        // No signal for completions the submitter already has, or is about to get: they were
        // sent before this check, and the submitter looks for completions once more after it
        // stops polling, so it cannot miss them.
        if self.received.count.load(Ordering::SeqCst) >= self.sent
            || self.received.polling.load(Ordering::SeqCst)
        {
            return;
        }
        if let Err(err) = self.evt.write(1) {
            error!("Failed to signal block IO completion: {:?}", err);
        }
        self.last = Instant::now();
    }
}

fn run_worker(
    mut file: File,
    batches: mpsc::Receiver<Vec<Op>>,
    completions: mpsc::Sender<ThreadedCompletion>,
    completion_evt: EventFd,
    received: Arc<Received>,
) {
    if let Some(filter) = worker_seccomp_filter()
        && let Err(err) = crate::seccomp::apply_filter(filter)
    {
        panic!("Failed to set the requested seccomp filters on the block IO worker: {err}");
    }

    let mut signal = CompletionSignal::new(completion_evt, received);
    let mut queue = VecDeque::new();
    loop {
        let op = match queue.pop_front() {
            Some(op) => op,
            None => {
                // Never go to sleep on a completion the device has not been told about.
                signal.flush();
                match batches.recv() {
                    Ok(batch) => {
                        queue.extend(batch);
                        continue;
                    }
                    Err(mpsc::RecvError) => break,
                }
            }
        };

        let completion = match op {
            Op::Io { io, req } => ThreadedCompletion {
                req,
                result: io.execute(&file),
            },
            Op::UpdateFile(new_file) => {
                file = new_file;
                continue;
            }
            Op::Barrier(ack) => {
                // The submitter may have given up waiting; nothing to do about it here.
                let _ = ack.send(());
                continue;
            }
            Op::Exit => break,
        };

        if completions.send(completion).is_err() {
            break;
        }
        signal.sent += 1;
        signal.pending = true;

        // Hold the signal back while more requests are queued, so that the device handles a
        // burst of completions at once instead of raising an interrupt for each. Only while the
        // previous signal is recent, though: a slow backing file gets one after every request.
        if queue.is_empty()
            && let Ok(batch) = batches.try_recv()
        {
            queue.extend(batch);
        }
        if queue.is_empty() {
            signal.flush();
        } else {
            signal.maybe_flush();
        }
    }
    signal.flush();
}

/// Front end of the threaded engine, used from the thread that owns the device.
#[derive(Debug)]
pub struct ThreadedFileEngine {
    file: File,
    batches: mpsc::Sender<Vec<Op>>,
    // Requests pushed since the last kick.
    batch: Vec<Op>,
    completions: mpsc::Receiver<ThreadedCompletion>,
    // Completions received while polling, not popped yet.
    ready: VecDeque<ThreadedCompletion>,
    completion_evt: EventFd,
    in_flight: usize,
    received: Arc<Received>,
    // Whether the backing file has been answering within the poll budget.
    poll_pays: bool,
    poll_budget: Option<Duration>,
    last_kick: Instant,
    worker: Option<thread::JoinHandle<()>>,
}

impl ThreadedFileEngine {
    pub fn from_file(file: File) -> Result<ThreadedFileEngine, ThreadedIoError> {
        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(ThreadedIoError::EventFd)?;
        let worker_evt = completion_evt
            .try_clone()
            .map_err(ThreadedIoError::EventFd)?;
        let worker_file = file.try_clone().map_err(ThreadedIoError::FileClone)?;
        let (batches, worker_batches) = mpsc::channel();
        let (worker_completions, completions) = mpsc::channel();
        let received = Arc::new(Received::default());
        let worker_received = received.clone();

        let worker = thread::Builder::new()
            .name("fc_blk_io".to_string())
            .spawn(move || {
                run_worker(
                    worker_file,
                    worker_batches,
                    worker_completions,
                    worker_evt,
                    worker_received,
                )
            })
            .map_err(ThreadedIoError::Spawn)?;

        Ok(ThreadedFileEngine {
            file,
            batches,
            batch: Vec::new(),
            completions,
            ready: VecDeque::new(),
            completion_evt,
            in_flight: 0,
            received,
            // Tests expect completions to take the completion event, unless they ask for this.
            poll_pays: !cfg!(test),
            poll_budget: (!cfg!(test)).then_some(POLL_BUDGET),
            last_kick: Instant::now(),
            worker: Some(worker),
        })
    }

    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Update the backing file of the engine
    pub fn update_file(&mut self, file: File) -> Result<(), ThreadedIoError> {
        let worker_file = file.try_clone().map_err(ThreadedIoError::FileClone)?;
        self.send(Op::UpdateFile(worker_file))?;
        self.file = file;
        Ok(())
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    /// Hand the requests pushed since the last kick to the worker.
    pub fn kick(&mut self) -> Result<(), ThreadedIoError> {
        if self.batch.is_empty() {
            return Ok(());
        }
        self.last_kick = Instant::now();
        self.batches
            .send(std::mem::take(&mut self.batch))
            .map_err(|_| ThreadedIoError::WorkerGone)
    }

    /// Send a control op, behind everything pushed so far.
    fn send(&mut self, op: Op) -> Result<(), ThreadedIoError> {
        self.batch.push(op);
        self.kick()
    }

    fn push(&mut self, io: Io, req: PendingRequest) -> Result<(), RequestError<ThreadedIoError>> {
        if self.in_flight >= THREADED_IO_MAX_IN_FLIGHT {
            return Err(RequestError {
                req,
                error: ThreadedIoError::QueueFull,
            });
        }

        self.batch.push(Op::Io { io, req });
        self.in_flight += 1;
        Ok(())
    }

    pub fn push_readv(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        segments: Vec<Segment>,
        req: PendingRequest,
    ) -> Result<(), RequestError<ThreadedIoError>> {
        let io = Io::Read {
            offset,
            mem: mem.clone(),
            segments,
        };
        self.push(io, req)
    }

    pub fn push_writev(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        segments: Vec<Segment>,
        req: PendingRequest,
    ) -> Result<(), RequestError<ThreadedIoError>> {
        let io = Io::Write {
            offset,
            mem: mem.clone(),
            segments,
        };
        self.push(io, req)
    }

    pub fn push_read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<ThreadedIoError>> {
        self.push_readv(offset, mem, vec![(addr, count)], req)
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<ThreadedIoError>> {
        self.push_writev(offset, mem, vec![(addr, count)], req)
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<ThreadedIoError>> {
        self.push(Io::Flush, req)
    }

    /// Pop a finished request, if there is one.
    pub fn pop(&mut self) -> Option<ThreadedCompletion> {
        let completion = match self.ready.pop_front() {
            Some(completion) => completion,
            None => {
                let completion = self.receive()?;
                // Completions that take the slow path tell how fast the backing file is.
                if self.in_flight == 1
                    && let Some(budget) = self.poll_budget
                {
                    self.poll_pays = self.last_kick.elapsed() < budget;
                }
                completion
            }
        };
        self.in_flight -= 1;
        Some(completion)
    }

    /// Take a completion from the worker, and let it know.
    fn receive(&mut self) -> Option<ThreadedCompletion> {
        let completion = self.completions.try_recv().ok()?;
        self.received.count.fetch_add(1, Ordering::SeqCst);
        Some(completion)
    }

    /// Turn waiting for completions after a kick on or off, see [`Self::kick_and_poll`].
    pub fn set_poll_budget(&mut self, budget: Option<Duration>) {
        self.poll_budget = budget;
        self.poll_pays = budget.is_some();
    }

    /// Hand the requests pushed since the last kick to the worker, then wait for the completions
    /// of everything in flight, for up to the poll budget. Only while the backing file has been
    /// answering within it, and with no more than [`POLL_MAX_IN_FLIGHT`] requests to wait for.
    /// Returns whether there are completions to pop.
    ///
    /// The worker does not signal the completions it finishes meanwhile.
    pub fn kick_and_poll(&mut self) -> Result<bool, ThreadedIoError> {
        let waiting_for = self.in_flight - self.ready.len();
        let budget = match self.poll_budget {
            Some(budget) if self.poll_pays && (1..=POLL_MAX_IN_FLIGHT).contains(&waiting_for) => {
                budget
            }
            _ => {
                self.kick()?;
                return Ok(!self.ready.is_empty());
            }
        };

        // Before the worker gets the requests, so that it signals none of them.
        self.received.polling.store(true, Ordering::SeqCst);
        let kicked = self.kick();
        let deadline = Instant::now() + budget;
        while kicked.is_ok() {
            while let Some(completion) = self.receive() {
                self.ready.push_back(completion);
            }
            if self.in_flight == self.ready.len() {
                break;
            }
            if Instant::now() >= deadline {
                // Too slow to wait for. Completions popped later say when that changes.
                self.poll_pays = false;
                break;
            }
            std::hint::spin_loop();
        }
        self.received.polling.store(false, Ordering::SeqCst);
        // What the worker finished before it could see the flag cleared went unsignalled.
        while let Some(completion) = self.receive() {
            self.ready.push_back(completion);
        }

        kicked.map(|_| !self.ready.is_empty())
    }

    /// Wait for every submitted request to complete. Their completions are left to be popped,
    /// unless `discard` is set.
    pub fn drain(&mut self, discard: bool) -> Result<(), ThreadedIoError> {
        if self.in_flight > 0 {
            let (ack, done) = mpsc::sync_channel(1);
            self.send(Op::Barrier(ack))?;
            done.recv().map_err(|_| ThreadedIoError::WorkerGone)?;
        }

        if discard {
            while self.pop().is_some() {}
        }

        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard: bool) -> Result<(), ThreadedIoError> {
        self.drain(discard)?;

        // Sync data out to physical media on host. The worker holds no data of its own, so the
        // file descriptor here reaches everything it wrote.
        self.file.sync_all().map_err(ThreadedIoError::SyncAll)
    }
}

impl Drop for ThreadedFileEngine {
    fn drop(&mut self) {
        // The worker only exits once it gets here, so everything submitted before is finished.
        let _ = self.send(Op::Exit);
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            error!("The block IO worker thread panicked");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    use vm_memory::GuestMemoryRegion;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::utils::u64_to_usize;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::{Bitmap, Bytes, GuestRegionMmapExt};

    const FILE_LEN: u32 = 1024;
    // 2 pages of memory should be enough to test read/write ops and also dirty tracking.
    const MEM_LEN: usize = 8192;

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

    fn check_dirty_mem(mem: &GuestMemoryMmap, addr: GuestAddress, len: u32, dirty: bool) {
        let bitmap = mem.find_region(addr).unwrap().bitmap();
        for offset in addr.0..addr.0 + u64::from(len) {
            assert_eq!(bitmap.dirty_at(u64_to_usize(offset)), dirty);
        }
    }

    fn new_engine() -> ThreadedFileEngine {
        ThreadedFileEngine::from_file(TempFile::new().unwrap().into_file()).unwrap()
    }

    fn assert_completed(engine: &mut ThreadedFileEngine, count: u32) {
        engine.drain(false).unwrap();
        assert_eq!(engine.pop().unwrap().result.unwrap(), count);
    }

    fn wait_for_signal(engine: &ThreadedFileEngine) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while engine.completion_evt().read().is_err() {
            assert!(Instant::now() < deadline, "completion never signalled");
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn test_read_write_flush() {
        let mut engine = new_engine();
        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();

        // Partial write and read, at the end of guest memory.
        let partial_len = 50;
        let addr = GuestAddress(MEM_LEN as u64 - u64::from(partial_len));
        let mem = create_mem();
        mem.write(&data, addr).unwrap();
        engine
            .push_write(0, &mem, addr, partial_len, PendingRequest::default())
            .unwrap();
        assert_completed(&mut engine, partial_len);
        let mem = create_mem();
        engine
            .push_read(0, &mem, addr, partial_len, PendingRequest::default())
            .unwrap();
        assert_completed(&mut engine, partial_len);
        let mut buf = vec![0u8; partial_len as usize];
        mem.read_slice(&mut buf, addr).unwrap();
        assert_eq!(buf, data[..partial_len as usize]);

        // Full write and read, at an offset.
        let mem = create_mem();
        mem.write(&data, GuestAddress(0)).unwrap();
        engine
            .push_write(
                100,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        assert_completed(&mut engine, FILE_LEN);
        let mem = create_mem();
        engine
            .push_read(
                100,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        assert_completed(&mut engine, FILE_LEN);
        let mut buf = vec![0u8; FILE_LEN as usize];
        mem.read_slice(&mut buf, GuestAddress(0)).unwrap();
        assert_eq!(buf, data);

        // Reads from the worker thread are accounted for in the dirty bitmap.
        check_dirty_mem(&mem, GuestAddress(0), FILE_LEN, true);
        check_dirty_mem(&mem, GuestAddress(4096), 4096, false);

        // Out of bounds guest memory fails the request, not the engine.
        engine
            .push_read(
                0,
                &mem,
                GuestAddress(MEM_LEN as u64),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        engine.drain(false).unwrap();
        assert!(matches!(
            engine.pop().unwrap().result,
            Err(ThreadedIoError::GuestMemory(_))
        ));

        engine.push_flush(PendingRequest::default()).unwrap();
        assert_completed(&mut engine, 0);
        engine.drain_and_flush(true).unwrap();
    }

    #[test]
    fn test_vectored() {
        let mut engine = new_engine();
        let data = vmm_sys_util::rand::rand_alphanumerics(3072)
            .as_bytes()
            .to_vec();

        // Write three buffers that are neither adjacent nor in order in guest memory.
        let mem = create_mem();
        let segments = vec![
            (GuestAddress(4096), 1024),
            (GuestAddress(0), 512),
            (GuestAddress(2048), 1536),
        ];
        mem.write_slice(&data[..1024], GuestAddress(4096)).unwrap();
        mem.write_slice(&data[1024..1536], GuestAddress(0)).unwrap();
        mem.write_slice(&data[1536..], GuestAddress(2048)).unwrap();
        engine
            .push_writev(512, &mem, segments, PendingRequest::default())
            .unwrap();
        assert_completed(&mut engine, 3072);

        // Read them back into different buffers, both in the first page.
        let mem = create_mem();
        let segments = vec![(GuestAddress(1024), 2048), (GuestAddress(0), 1024)];
        engine
            .push_readv(512, &mem, segments, PendingRequest::default())
            .unwrap();
        assert_completed(&mut engine, 3072);
        let mut buf = vec![0u8; 3072];
        mem.read_slice(&mut buf[..2048], GuestAddress(1024))
            .unwrap();
        mem.read_slice(&mut buf[2048..], GuestAddress(0)).unwrap();
        assert_eq!(buf, data);

        // The page read into is dirty, the other one is not.
        check_dirty_mem(&mem, GuestAddress(0), 4096, true);
        check_dirty_mem(&mem, GuestAddress(4096), 4096, false);

        // One bad buffer fails the whole request, before any of it is transferred.
        let mem = create_mem();
        let segments = vec![(GuestAddress(0), 512), (GuestAddress(MEM_LEN as u64), 512)];
        engine
            .push_readv(512, &mem, segments, PendingRequest::default())
            .unwrap();
        engine.drain(false).unwrap();
        assert!(matches!(
            engine.pop().unwrap().result,
            Err(ThreadedIoError::GuestMemory(_))
        ));
        check_dirty_mem(&mem, GuestAddress(0), 512, false);

        // Reading past the end of the file is an error, not a short read.
        let mem = create_mem();
        engine
            .push_read(3072, &mem, GuestAddress(0), 1024, PendingRequest::default())
            .unwrap();
        engine.drain(false).unwrap();
        assert!(matches!(
            engine.pop().unwrap().result,
            Err(ThreadedIoError::Read(_))
        ));
    }

    #[test]
    fn test_batching() {
        let mem = create_mem();
        let mut engine = new_engine();

        // Nothing reaches the worker until the kick.
        for _ in 0..4 {
            engine
                .push_write(
                    0,
                    &mem,
                    GuestAddress(0),
                    FILE_LEN,
                    PendingRequest::default(),
                )
                .unwrap();
        }
        thread::sleep(Duration::from_millis(50));
        engine.completion_evt().read().unwrap_err();
        assert!(engine.pop().is_none());

        engine.kick().unwrap();
        let mut completed = 0;
        while completed < 4 {
            wait_for_signal(&engine);
            while let Some(completion) = engine.pop() {
                assert_eq!(completion.result.unwrap(), FILE_LEN);
                completed += 1;
            }
        }
        // A kick with nothing pushed is a no-op.
        engine.kick().unwrap();
        assert!(engine.pop().is_none());
    }

    #[test]
    fn test_kick_and_poll() {
        let mem = create_mem();
        let mut engine = new_engine();
        let push = |engine: &mut ThreadedFileEngine, count| {
            for _ in 0..count {
                engine
                    .push_write(
                        0,
                        &mem,
                        GuestAddress(0),
                        FILE_LEN,
                        PendingRequest::default(),
                    )
                    .unwrap();
            }
        };

        // With time to wait, everything in flight completes in the call, unsignalled.
        engine.set_poll_budget(Some(Duration::from_secs(10)));
        push(&mut engine, POLL_MAX_IN_FLIGHT);
        assert!(engine.kick_and_poll().unwrap());
        engine.completion_evt().read().unwrap_err();
        for _ in 0..POLL_MAX_IN_FLIGHT {
            assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
        }
        assert!(engine.pop().is_none());

        // With more in flight than that, completions are signalled, and polling stays on.
        push(&mut engine, POLL_MAX_IN_FLIGHT + 1);
        assert!(!engine.kick_and_poll().unwrap());
        assert!(engine.poll_pays);
        engine.drain(false).unwrap();
        wait_for_signal(&engine);
        for _ in 0..=POLL_MAX_IN_FLIGHT {
            assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
        }
        assert!(engine.poll_pays);
        // Nothing in flight, nothing to wait for.
        assert!(!engine.kick_and_poll().unwrap());

        // With no time to wait, completions are signalled, and polling stops...
        engine.set_poll_budget(Some(Duration::ZERO));
        push(&mut engine, 1);
        assert!(!engine.kick_and_poll().unwrap());
        assert!(!engine.poll_pays);
        wait_for_signal(&engine);
        assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
        assert!(!engine.poll_pays);
        push(&mut engine, 1);
        assert!(!engine.kick_and_poll().unwrap());
        wait_for_signal(&engine);

        // ...until a completion shows the backing file answers within the budget again.
        engine.poll_budget = Some(Duration::from_secs(10));
        assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
        assert!(engine.poll_pays);
        push(&mut engine, 2);
        assert!(engine.kick_and_poll().unwrap());
        engine.completion_evt().read().unwrap_err();
        assert_eq!(engine.in_flight, 2);
        engine.drain(true).unwrap();
        assert_eq!(engine.in_flight, 0);

        // Turned off, a kick is only a kick.
        engine.set_poll_budget(None);
        push(&mut engine, 1);
        assert!(!engine.kick_and_poll().unwrap());
        wait_for_signal(&engine);
        assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
    }

    #[test]
    fn test_completions_are_signalled() {
        let mem = create_mem();
        let mut engine = new_engine();

        // Submitting returns before the IO is done: completions only show up through the
        // completion eventfd, once the worker has finished them.
        for _ in 0..10 {
            engine
                .push_write(
                    0,
                    &mem,
                    GuestAddress(0),
                    FILE_LEN,
                    PendingRequest::default(),
                )
                .unwrap();
        }
        engine.kick().unwrap();
        let mut completed = 0;
        while completed < 10 {
            wait_for_signal(&engine);
            while let Some(completion) = engine.pop() {
                assert_eq!(completion.result.unwrap(), FILE_LEN);
                completed += 1;
            }
        }
        assert!(engine.pop().is_none());
    }

    #[test]
    fn test_signal_before_idle() {
        let mem = create_mem();
        let mut engine = new_engine();

        // Queue ops that complete nothing behind a request: the worker must still signal the
        // request's completion before it goes idle.
        engine
            .push_write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        engine
            .update_file(TempFile::new().unwrap().into_file())
            .unwrap();

        wait_for_signal(&engine);
        assert_eq!(engine.pop().unwrap().result.unwrap(), FILE_LEN);
    }

    #[test]
    fn test_throttling() {
        let mut engine = new_engine();

        for _ in 0..THREADED_IO_MAX_IN_FLIGHT {
            engine.push_flush(PendingRequest::default()).unwrap();
        }
        // Completed but not yet popped requests still count as in flight.
        engine.drain(false).unwrap();
        let err = engine.push_flush(PendingRequest::default()).unwrap_err();
        assert!(matches!(err.error, ThreadedIoError::QueueFull));

        // Popping a completion makes room for one more request.
        engine.pop().unwrap();
        engine.push_flush(PendingRequest::default()).unwrap();
        let err = engine.push_flush(PendingRequest::default()).unwrap_err();
        assert!(matches!(err.error, ThreadedIoError::QueueFull));

        // Discarding all completions makes room for all of them.
        engine.drain(true).unwrap();
        assert!(engine.pop().is_none());
        for _ in 0..THREADED_IO_MAX_IN_FLIGHT {
            engine.push_flush(PendingRequest::default()).unwrap();
        }
        engine.drain(true).unwrap();
    }

    #[test]
    fn test_update_file() {
        let mem = create_mem();
        let old = TempFile::new().unwrap();
        let new = TempFile::new().unwrap();
        let mut engine = ThreadedFileEngine::from_file(old.as_file().try_clone().unwrap()).unwrap();

        let data = vmm_sys_util::rand::rand_alphanumerics(FILE_LEN as usize)
            .as_bytes()
            .to_vec();
        mem.write(&data, GuestAddress(0)).unwrap();

        // Requests submitted before the update go to the old file, the ones after to the new one,
        // without waiting for the first to complete.
        engine
            .push_write(
                0,
                &mem,
                GuestAddress(0),
                FILE_LEN,
                PendingRequest::default(),
            )
            .unwrap();
        engine
            .update_file(new.as_file().try_clone().unwrap())
            .unwrap();
        engine
            .push_write(0, &mem, GuestAddress(0), 10, PendingRequest::default())
            .unwrap();
        engine.drain(true).unwrap();

        assert_eq!(old.as_file().metadata().unwrap().len(), u64::from(FILE_LEN));
        assert_eq!(new.as_file().metadata().unwrap().len(), 10);
        assert_eq!(
            engine.file().metadata().unwrap().ino(),
            new.as_file().metadata().unwrap().ino()
        );
    }
}
