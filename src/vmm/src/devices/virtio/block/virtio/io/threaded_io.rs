// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Threaded file engine.
//!
//! Each drive gets a worker thread that serves its virtqueue on its own, with blocking IO: it
//! waits on the queue's eventfd and the rate limiter's timer, parses and rate-limits requests,
//! reads and writes the backing file with `preadv`/`pwritev`, fills the used ring and raises the
//! guest interrupt. A slow backing file then stalls only its own worker, not the event loop and
//! every other device serviced there, and no io_uring support is needed.
//!
//! The event loop only sends the worker control messages: start and stop serving the queue, kick
//! it, swap the backing file, and wait for it.

use std::fs::File;
use std::mem::ManuallyDrop;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;

use vm_memory::GuestMemoryError;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;

use super::{BlockIoError, RequestError};
use crate::devices::virtio::block::virtio::metrics::BlockDeviceMetrics;
use crate::devices::virtio::block::virtio::{
    FinishedRequest, IoErr, PendingRequest, Request, RequestType, SECTOR_SHIFT, VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, error};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::seccomp::{BpfProgram, BpfProgramRef};
use crate::vstate::memory::{
    Bytes, GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap,
};

/// A guest buffer: its address and length.
pub type Segment = (GuestAddress, u32);

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

/// The prefix of the worker thread names; the rest is the start of the drive id. Linux keeps 15
/// bytes of a thread name, which leaves 11 for the drive id.
const THREAD_NAME_PREFIX: &str = "blk_";

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
    /// Epoll: {0}
    Epoll(std::io::Error),
    /// Cloning the backing file: {0}
    FileClone(std::io::Error),
    /// Spawning the IO worker thread: {0}
    Spawn(std::io::Error),
    /// The IO worker thread is gone
    WorkerGone,
    /// Requests are served by the IO worker thread
    ServedByWorker,
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

/// What the worker needs to serve a device's queue, from its activation on.
#[derive(Debug)]
pub struct Serving {
    /// The virtqueue. The worker owns it until it stops, and hands it back then.
    pub queue: Queue,
    /// The queue's eventfd. It stays the device's: the worker only waits on it, and stops before
    /// the device closes it.
    pub queue_evt: RawFd,
    pub mem: GuestMemoryMmap,
    pub interrupt: Arc<dyn VirtioInterrupt>,
    pub metrics: Arc<BlockDeviceMetrics>,
    pub nsectors: u64,
    pub image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
    pub drive_id: String,
}

#[derive(Debug)]
enum Control {
    Start(Box<Serving>, Arc<Mutex<RateLimiter>>),
    Stop,
    Kick,
    UpdateDisk {
        file: File,
        nsectors: u64,
        image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
    },
    SyncAll,
    Barrier,
    Exit,
}

#[derive(Debug)]
enum Reply {
    Stopped(Option<Queue>),
    Synced(Result<(), std::io::Error>),
    Done,
}

// Epoll tokens.
const CONTROL: u64 = 0;
const QUEUE: u64 = 1;
const RATE_LIMITER: u64 = 2;

/// The worker's state while it serves the queue.
#[derive(Debug)]
struct Active {
    queue: Queue,
    queue_evt: ManuallyDrop<EventFd>,
    mem: GuestMemoryMmap,
    interrupt: Arc<dyn VirtioInterrupt>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    rate_limiter_fd: RawFd,
    metrics: Arc<BlockDeviceMetrics>,
    nsectors: u64,
    image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
}

#[derive(Debug)]
struct Worker {
    file: File,
    epoll: Epoll,
    control_evt: EventFd,
    control: mpsc::Receiver<Control>,
    replies: mpsc::Sender<Reply>,
    active: Option<Active>,
}

impl Worker {
    fn run(mut self) {
        if let Some(filter) = worker_seccomp_filter()
            && let Err(err) = crate::seccomp::apply_filter(filter)
        {
            panic!("Failed to set the requested seccomp filters on the block IO worker: {err}");
        }

        let mut events = [EpollEvent::default(); 4];
        loop {
            let count = match self.epoll.wait(-1, &mut events) {
                Ok(count) => count,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    error!("Block IO worker failed to wait for events: {:?}", err);
                    return;
                }
            };
            for event in &events[..count] {
                match event.data() {
                    CONTROL => {
                        let _ = self.control_evt.read();
                        while let Ok(control) = self.control.try_recv() {
                            if !self.handle(control) {
                                return;
                            }
                        }
                    }
                    QUEUE => self.queue_event(),
                    RATE_LIMITER => self.rate_limiter_event(),
                    _ => {}
                }
            }
        }
    }

    /// Handle a control message. Returns false when the worker has to exit.
    fn handle(&mut self, control: Control) -> bool {
        match control {
            Control::Start(serving, rate_limiter) => self.start(*serving, rate_limiter),
            Control::Stop => {
                let queue = self.stop();
                let _ = self.replies.send(Reply::Stopped(queue));
            }
            Control::Kick => self.process_queue(),
            Control::UpdateDisk {
                file,
                nsectors,
                image_id,
            } => {
                self.file = file;
                if let Some(active) = self.active.as_mut() {
                    active.nsectors = nsectors;
                    active.image_id = image_id;
                }
                let _ = self.replies.send(Reply::Done);
            }
            Control::SyncAll => {
                let _ = self.replies.send(Reply::Synced(self.file.sync_all()));
            }
            Control::Barrier => {
                let _ = self.replies.send(Reply::Done);
            }
            Control::Exit => {
                self.stop();
                return false;
            }
        }
        true
    }

    fn start(&mut self, serving: Serving, rate_limiter: Arc<Mutex<RateLimiter>>) {
        let name = format!("{THREAD_NAME_PREFIX}{}", serving.drive_id);
        let mut name = name.into_bytes();
        name.truncate(15);
        name.push(0);
        // SAFETY: `name` is NUL terminated, and at most 16 bytes long, as PR_SET_NAME expects.
        unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };

        let rate_limiter_fd = rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock")
            .as_raw_fd();
        for (fd, token) in [(serving.queue_evt, QUEUE), (rate_limiter_fd, RATE_LIMITER)] {
            if let Err(err) = self.epoll.ctl(
                ControlOperation::Add,
                fd,
                EpollEvent::new(EventSet::IN, token),
            ) {
                error!("Block IO worker failed to watch fd {}: {:?}", fd, err);
            }
        }

        self.active = Some(Active {
            queue: serving.queue,
            // SAFETY: the fd is the device's, which keeps it open until it has stopped the
            // worker. `ManuallyDrop` keeps the worker from closing it.
            queue_evt: ManuallyDrop::new(unsafe { EventFd::from_raw_fd(serving.queue_evt) }),
            mem: serving.mem,
            interrupt: serving.interrupt,
            rate_limiter,
            rate_limiter_fd,
            metrics: serving.metrics,
            nsectors: serving.nsectors,
            image_id: serving.image_id,
        });
        // Serve what the guest queued before the worker was watching.
        self.process_queue();
    }

    /// Stop serving the queue, and return it.
    fn stop(&mut self) -> Option<Queue> {
        let active = self.active.take()?;
        for fd in [active.queue_evt.as_raw_fd(), active.rate_limiter_fd] {
            let _ = self
                .epoll
                .ctl(ControlOperation::Delete, fd, EpollEvent::default());
        }
        // Dropping the rest, the rate limiter included, before the device gets the queue.
        Some(active.queue)
    }

    fn queue_event(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        active.metrics.queue_event_count.inc();
        if let Err(err) = active.queue_evt.read() {
            error!("Failed to get queue event: {:?}", err);
            active.metrics.event_fails.inc();
        } else if active
            .rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock")
            .is_blocked()
        {
            active.metrics.rate_limiter_throttled_events.inc();
        } else {
            self.process_queue();
        }
    }

    fn rate_limiter_event(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        active.metrics.rate_limiter_event_count.inc();
        let refilled = active
            .rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock")
            .event_handler()
            .is_ok();
        if refilled {
            self.process_queue();
        }
    }

    /// Serve every request available, until the queue is empty or the rate limiter blocks.
    fn process_queue(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let mut used_any = false;

        loop {
            let head = match active.queue.pop_or_enable_notification() {
                Ok(Some(head)) => head,
                Ok(None) => break,
                Err(err) => panic!("Block queue is corrupt: {err}"),
            };
            active
                .metrics
                .remaining_reqs_count
                .add(active.queue.len().into());

            let parsed = Request::parse(&head, &active.mem, active.nsectors);
            let finished = match parsed {
                Ok(request) => {
                    let limited = request.rate_limit(
                        &mut active
                            .rate_limiter
                            .lock()
                            .expect("Poisoned block rate limiter lock"),
                    );
                    if limited {
                        // Leave it in the avail ring until the rate limiter's timer fires.
                        active.queue.undo_pop();
                        active.metrics.rate_limiter_throttled_events.inc();
                        break;
                    }
                    execute(&self.file, active, request, head.index)
                }
                Err(err) => {
                    error!("Failed to parse available descriptor chain: {:?}", err);
                    active.metrics.execute_fails.inc();
                    FinishedRequest {
                        num_bytes_to_mem: 0,
                        desc_idx: head.index,
                    }
                }
            };

            used_any = true;
            active
                .queue
                .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                .unwrap_or_else(|err| {
                    error!(
                        "Failed to add available descriptor head {}: {}",
                        finished.desc_idx, err
                    )
                });
        }
        active.queue.advance_used_ring_idx();

        if used_any && active.queue.prepare_kick() {
            active
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    active.metrics.event_fails.inc();
                });
        }
        if !used_any {
            active.metrics.no_avail_buffer.inc();
        }
    }
}

/// Perform a request with blocking IO, write its status, and return what to put in the used
/// ring.
fn execute(file: &File, active: &Active, request: Request, desc_idx: u16) -> FinishedRequest {
    let (mem, metrics) = (&active.mem, &*active.metrics);
    let pending = request.to_pending_request(desc_idx);
    let file_error = |err| IoErr::FileEngine(BlockIoError::Threaded(err));

    let result = match request.r#type {
        RequestType::In | RequestType::Out => {
            let segments = [(request.data_addr, request.data_len)];
            let offset = request.sector << SECTOR_SHIFT;
            if request.r#type == RequestType::In {
                let _metric = metrics.read_agg.record_latency_metrics();
                let result = transfer(file, Direction::Read, offset, mem, &segments);
                if result.is_ok() {
                    // The guest memory was written from this thread, so account for it in the
                    // dirty bitmap before the guest gets to see the completion.
                    for &(addr, len) in &segments {
                        mem.mark_dirty(addr, len as usize);
                    }
                }
                result.map_err(file_error)
            } else {
                let _metric = metrics.write_agg.record_latency_metrics();
                transfer(file, Direction::Write, offset, mem, &segments).map_err(file_error)
            }
        }
        // Sync data out to physical media on host.
        RequestType::Flush => file
            .sync_all()
            .map(|_| 0)
            .map_err(|err| file_error(ThreadedIoError::SyncAll(err))),
        RequestType::GetDeviceID => mem
            .write_slice(&active.image_id, request.data_addr)
            .map(|_| VIRTIO_BLK_ID_BYTES)
            .map_err(IoErr::GetId),
        RequestType::Unsupported(_) => Ok(0),
    };

    pending.finish(mem, result, metrics)
}

/// Front end of the threaded engine, used from the thread that owns the device.
#[derive(Debug)]
pub struct ThreadedFileEngine {
    control: mpsc::Sender<Control>,
    control_evt: EventFd,
    replies: mpsc::Receiver<Reply>,
    // While the worker serves the queue: the rate limiter it shares with the device.
    rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
    // Takes the device's rate limiter's place while the worker has it. Made here, before the VMM
    // thread's seccomp filter forbids creating the timerfd a rate limiter needs.
    spare_rate_limiter: Option<RateLimiter>,
    // A new backing file, until the device hands it over with its properties.
    new_file: Option<File>,
    #[cfg(test)]
    file: File,
    worker: Option<thread::JoinHandle<()>>,
}

impl ThreadedFileEngine {
    pub fn from_file(file: File) -> Result<ThreadedFileEngine, ThreadedIoError> {
        let control_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(ThreadedIoError::EventFd)?;
        let worker_control_evt = control_evt.try_clone().map_err(ThreadedIoError::EventFd)?;
        // Before the worker applies its seccomp filter, which does not allow creating it.
        let epoll = Epoll::new().map_err(ThreadedIoError::Epoll)?;
        epoll
            .ctl(
                ControlOperation::Add,
                worker_control_evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN, CONTROL),
            )
            .map_err(ThreadedIoError::Epoll)?;
        #[cfg(test)]
        let test_file = file.try_clone().map_err(ThreadedIoError::FileClone)?;
        let (control, worker_control) = mpsc::channel();
        let (worker_replies, replies) = mpsc::channel();

        let worker = Worker {
            file,
            epoll,
            control_evt: worker_control_evt,
            control: worker_control,
            replies: worker_replies,
            active: None,
        };
        let worker = thread::Builder::new()
            .name("fc_blk_io".to_string())
            .spawn(move || worker.run())
            .map_err(ThreadedIoError::Spawn)?;

        Ok(ThreadedFileEngine {
            control,
            control_evt,
            replies,
            rate_limiter: None,
            spare_rate_limiter: Some(RateLimiter::default()),
            new_file: None,
            #[cfg(test)]
            file: test_file,
            worker: Some(worker),
        })
    }

    /// The backing file the engine was created with.
    #[cfg(test)]
    pub fn file(&self) -> &File {
        &self.file
    }

    fn send(&self, control: Control) -> Result<(), ThreadedIoError> {
        self.control
            .send(control)
            .map_err(|_| ThreadedIoError::WorkerGone)?;
        self.control_evt.write(1).map_err(ThreadedIoError::EventFd)
    }

    fn reply(&self) -> Result<Reply, ThreadedIoError> {
        self.replies.recv().map_err(|_| ThreadedIoError::WorkerGone)
    }

    /// Whether the worker serves the device's queue.
    pub fn is_serving(&self) -> bool {
        self.rate_limiter.is_some()
    }

    /// Hand the device's queue and rate limiter to the worker, which serves the queue from then
    /// on. The device gets a spare rate limiter in exchange, until [`Self::stop`].
    pub fn start(
        &mut self,
        serving: Serving,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<(), ThreadedIoError> {
        let Some(mut spare) = self.spare_rate_limiter.take() else {
            // Already serving.
            return Ok(());
        };
        std::mem::swap(device_rate_limiter, &mut spare);
        let rate_limiter = Arc::new(Mutex::new(spare));
        self.send(Control::Start(Box::new(serving), rate_limiter.clone()))?;
        self.rate_limiter = Some(rate_limiter);
        Ok(())
    }

    /// Have the worker stop serving the queue. Returns the queue, which the device gets back,
    /// and puts its rate limiter back.
    pub fn stop(
        &mut self,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<Option<Queue>, ThreadedIoError> {
        let Some(rate_limiter) = self.rate_limiter.take() else {
            return Ok(None);
        };
        self.send(Control::Stop)?;
        let queue = match self.reply()? {
            Reply::Stopped(queue) => queue,
            reply => panic!("Unexpected block IO worker reply to stop: {reply:?}"),
        };
        // The worker dropped its reference before replying.
        let mut rate_limiter = Arc::try_unwrap(rate_limiter)
            .expect("Block IO worker kept the rate limiter")
            .into_inner()
            .expect("Poisoned block rate limiter lock");
        std::mem::swap(device_rate_limiter, &mut rate_limiter);
        self.spare_rate_limiter = Some(rate_limiter);
        Ok(queue)
    }

    /// Have the worker look at the queue, as if the guest had notified it.
    pub fn kick(&self) -> Result<(), ThreadedIoError> {
        self.send(Control::Kick)
    }

    /// The rate limiter the worker uses, while it serves the queue.
    pub fn rate_limiter(&self) -> Option<&Arc<Mutex<RateLimiter>>> {
        self.rate_limiter.as_ref()
    }

    /// Update the rate limiter the worker uses. Returns the updates back when the worker does
    /// not serve the queue, for the device to apply to its own.
    pub fn update_rate_limiter(
        &self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Option<(BucketUpdate, BucketUpdate)> {
        match self.rate_limiter.as_ref() {
            Some(rate_limiter) => {
                rate_limiter
                    .lock()
                    .expect("Poisoned block rate limiter lock")
                    .update_buckets(bytes, ops);
                None
            }
            None => Some((bytes, ops)),
        }
    }

    /// Take a new backing file. The worker switches to it with [`Self::update_disk`].
    pub fn update_file(&mut self, file: File) -> Result<(), ThreadedIoError> {
        // No clone of it: the VMM thread's seccomp filter does not allow one after boot.
        self.new_file = Some(file);
        Ok(())
    }

    /// Switch the worker to the backing file given to [`Self::update_file`], with its size and
    /// id, at once. Requests the worker served before use the old file, later ones the new one.
    pub fn update_disk(
        &mut self,
        nsectors: u64,
        image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
    ) -> Result<(), ThreadedIoError> {
        let Some(file) = self.new_file.take() else {
            return Ok(());
        };
        self.send(Control::UpdateDisk {
            file,
            nsectors,
            image_id,
        })?;
        match self.reply()? {
            Reply::Done => Ok(()),
            reply => panic!("Unexpected block IO worker reply to a disk update: {reply:?}"),
        }
    }

    /// Wait for the worker to finish the request it is serving, if any.
    pub fn drain(&mut self, _discard: bool) -> Result<(), ThreadedIoError> {
        self.send(Control::Barrier)?;
        match self.reply()? {
            Reply::Done => Ok(()),
            reply => panic!("Unexpected block IO worker reply to a barrier: {reply:?}"),
        }
    }

    pub fn drain_and_flush(&mut self, _discard: bool) -> Result<(), ThreadedIoError> {
        // Sync data out to physical media on host, from the worker, which has the backing file.
        // It finishes what it is serving first.
        self.send(Control::SyncAll)?;
        match self.reply()? {
            Reply::Synced(result) => result.map_err(ThreadedIoError::SyncAll),
            reply => panic!("Unexpected block IO worker reply to a sync: {reply:?}"),
        }
    }

    /// Requests are served by the worker, from the queue. Should one get here, it fails.
    pub fn refuse(req: PendingRequest) -> RequestError<ThreadedIoError> {
        RequestError {
            req,
            error: ThreadedIoError::ServedByWorker,
        }
    }
}

impl Drop for ThreadedFileEngine {
    fn drop(&mut self) {
        let _ = self.send(Control::Exit);
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
    use vm_memory::GuestMemoryRegion;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::utils::u64_to_usize;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::{Bitmap, GuestRegionMmapExt};

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

    fn is_dirty(mem: &GuestMemoryMmap, addr: GuestAddress) -> bool {
        mem.find_region(addr)
            .unwrap()
            .bitmap()
            .dirty_at(u64_to_usize(addr.0))
    }

    #[test]
    fn test_transfer() {
        let file = TempFile::new().unwrap().into_file();
        let data: Vec<u8> = (0..3072u32).map(|i| (i % 251) as u8).collect();

        // Write three buffers that are neither adjacent nor in order in guest memory.
        let mem = create_mem();
        mem.write_slice(&data[..1024], GuestAddress(4096)).unwrap();
        mem.write_slice(&data[1024..1536], GuestAddress(0)).unwrap();
        mem.write_slice(&data[1536..], GuestAddress(2048)).unwrap();
        let segments = [
            (GuestAddress(4096), 1024),
            (GuestAddress(0), 512),
            (GuestAddress(2048), 1536),
        ];
        assert_eq!(
            transfer(&file, Direction::Write, 512, &mem, &segments).unwrap(),
            3072
        );

        // Read them back into different buffers.
        let mem = create_mem();
        let segments = [(GuestAddress(1024), 2048), (GuestAddress(6144), 1024)];
        assert_eq!(
            transfer(&file, Direction::Read, 512, &mem, &segments).unwrap(),
            3072
        );
        let mut buf = vec![0u8; 3072];
        mem.read_slice(&mut buf[..2048], GuestAddress(1024))
            .unwrap();
        mem.read_slice(&mut buf[2048..], GuestAddress(6144))
            .unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn test_transfer_errors() {
        let file = TempFile::new().unwrap().into_file();
        file.set_len(4096).unwrap();
        let mem = create_mem();

        // One bad buffer fails the whole request, before any of it is transferred.
        let segments = [(GuestAddress(0), 512), (GuestAddress(MEM_LEN as u64), 512)];
        assert!(matches!(
            transfer(&file, Direction::Read, 0, &mem, &segments),
            Err(ThreadedIoError::GuestMemory(_))
        ));
        assert!(!is_dirty(&mem, GuestAddress(0)));

        // Reading past the end of the file is an error, not a short read.
        assert!(matches!(
            transfer(
                &file,
                Direction::Read,
                3584,
                &mem,
                &[(GuestAddress(0), 1024)]
            ),
            Err(ThreadedIoError::Read(_))
        ));
    }

    #[test]
    fn test_engine_before_activation() {
        let old = TempFile::new().unwrap();
        let new = TempFile::new().unwrap();
        let mut engine = ThreadedFileEngine::from_file(old.as_file().try_clone().unwrap()).unwrap();
        assert!(!engine.is_serving());
        assert!(engine.rate_limiter().is_none());

        // Without a queue to serve, the worker still answers, and takes a new backing file.
        engine.drain(true).unwrap();
        engine.drain_and_flush(true).unwrap();
        engine
            .update_file(new.as_file().try_clone().unwrap())
            .unwrap();
        engine
            .update_disk(0, [0; VIRTIO_BLK_ID_BYTES as usize])
            .unwrap();
        engine.drain(false).unwrap();

        // Rate limiter updates are the device's to apply.
        let updates = engine.update_rate_limiter(BucketUpdate::None, BucketUpdate::Disabled);
        assert!(updates.is_some());

        // Stopping a worker that serves nothing returns nothing.
        let mut rate_limiter = RateLimiter::default();
        assert!(engine.stop(&mut rate_limiter).unwrap().is_none());
    }
}
