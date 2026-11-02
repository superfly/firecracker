// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NBD file engine.
//!
//! Serves a drive from an NBD server listening on a Unix socket, with the VMM as the NBD client:
//! the guest sees an ordinary virtio-blk disk, and no kernel NBD device is involved, on the host
//! or in the guest. As with the threaded engine, each drive gets a worker thread that owns its
//! virtqueue from activation on, so the event loop never waits on the server. Unlike it, the
//! worker does not block on a request: it sends every request it takes off the queue to the
//! server at once, keeps up to a queue's worth in flight, and completes them in whatever order
//! the server answers.
//!
//! When the connection drops, the worker reconnects, retrying for as long as it takes (a server
//! may refuse the export while it still holds it for the old connection), and resends every
//! request that had no answer. A server that answers ESHUTDOWN is treated the same way.
//!
//! Before a snapshot the worker stops taking requests off the queue, waits for those in flight,
//! and has the server flush, so the snapshot holds no request in flight and everything the guest
//! saw completed is on stable storage. If that cannot finish in time, stopping fails and the
//! worker carries on serving the queue.

use std::collections::VecDeque;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use vm_memory::GuestMemoryError;
use vmm_sys_util::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vmm_sys_util::eventfd::EventFd;

use super::threaded_io::{Segment, Serving, worker_seccomp_filter};
use super::{BlockIoError, RequestError};
use crate::devices::virtio::block::virtio::metrics::BlockDeviceMetrics;
use crate::devices::virtio::block::virtio::{
    IoErr, PendingRequest, Request, RequestType, SECTOR_SHIFT, VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, error, info, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::vstate::memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryExtension, GuestMemoryMmap,
};

/// Where a drive served by the NBD engine is: an NBD server on a Unix socket, and the name of
/// the export to ask it for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NbdBackendConfig {
    /// Path of the Unix socket the NBD server listens on.
    pub socket_path: String,
    /// Name of the export to serve the drive from.
    pub export_name: String,
}

// Handshake.
const NBD_MAGIC: u64 = 0x4e42_444d_4147_4943; // "NBDMAGIC"
const IHAVEOPT: u64 = 0x4948_4156_454F_5054; // "IHAVEOPT"
const OPT_REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
const FLAG_NO_ZEROES: u16 = 1 << 1;
const OPT_GO: u32 = 7;
const REP_ACK: u32 = 1;
const REP_INFO: u32 = 3;
const REP_ERR_BIT: u32 = 1 << 31;
const INFO_EXPORT: u16 = 0;

// Transmission flags.
const TFLAG_READ_ONLY: u16 = 1 << 1;
const TFLAG_SEND_FLUSH: u16 = 1 << 2;

// Transmission.
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;
const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_FLUSH: u16 = 3;
const REQUEST_HEADER_LEN: usize = 28;
const REPLY_HEADER_LEN: usize = 16;
/// The error a server answers with when it is shutting down: the request was not done, and
/// should be sent again once it is back.
const NBD_ESHUTDOWN: u32 = 108;

/// How long the drive's creation waits for the server, while it still refuses the export or is
/// not listening yet.
const INITIAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one handshake may take before the attempt is abandoned.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
/// The first and the longest wait between reconnection attempts.
const RECONNECT_DELAY_MIN: Duration = Duration::from_millis(5);
const RECONNECT_DELAY_MAX: Duration = Duration::from_millis(250);
/// How long stopping may wait for the requests in flight and the flush, before it gives up and
/// leaves the worker serving.
pub const NBD_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// One slot per descriptor head, which the guest cannot reuse while its request is in flight,
/// and one for the worker's own flush.
const FLUSH_SLOT: usize = FIRECRACKER_MAX_QUEUE_SIZE as usize;
const NUM_SLOTS: usize = FLUSH_SLOT + 1;

/// Size of the buffer replies are read into. A read's data goes straight into guest memory,
/// unless it arrived in the same read as its header.
const RECV_BUFFER_LEN: usize = 64 * 1024;
/// Most buffers one `writev` sends.
const MAX_IOVECS: usize = 1024;

/// The prefix of the worker thread names; the rest is the start of the drive id.
const THREAD_NAME_PREFIX: &str = "nbd_";

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NbdIoError {
    /// Connecting to the NBD server: {0}
    Connect(io::Error),
    /// NBD handshake: {0}
    Handshake(io::Error),
    /// NBD handshake: {0}
    Protocol(&'static str),
    /// The NBD server refused the export ({0:#x}): {1}
    Refused(u32, String),
    /// The NBD server failed the request: error {0}
    Server(u32),
    /// The NBD export's size {0} is not a whole number of sectors
    Size(u64),
    /// Guest memory: {0}
    GuestMemory(GuestMemoryError),
    /// Timed out waiting for the requests in flight and a flush
    StopTimeout,
    /// EventFd: {0}
    EventFd(io::Error),
    /// Epoll: {0}
    Epoll(io::Error),
    /// Spawning the IO worker thread: {0}
    Spawn(io::Error),
    /// The IO worker thread is gone
    WorkerGone,
    /// Requests are served by the IO worker thread
    ServedByWorker,
    /// A drive served over NBD has no backing file
    NoBackingFile,
}

/// An NBD connection in its transmission phase.
#[derive(Debug)]
struct Connection {
    fd: OwnedFd,
    size: u64,
    flags: u16,
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn read_full(fd: RawFd, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is valid for writes of its length.
        let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        match ret {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n if n > 0 => buf = &mut buf[n.unsigned_abs()..],
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

fn write_full(fd: RawFd, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        // SAFETY: `buf` is valid for reads of its length.
        let ret = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        match ret {
            n if n > 0 => buf = &buf[n.unsigned_abs()..],
            0 => return Err(io::ErrorKind::WriteZero.into()),
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let mut on: libc::c_int = 1;
    // SAFETY: FIONBIO reads one int, which `on` is.
    if unsafe { libc::ioctl(fd, libc::FIONBIO, &mut on) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Connect to the server and negotiate the export with fixed newstyle and NBD_OPT_GO. The
/// socket is left non-blocking, for the transmission phase.
fn connect(config: &NbdBackendConfig, timeout: Duration) -> Result<Connection, NbdIoError> {
    let stream = UnixStream::connect(&config.socket_path).map_err(NbdIoError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(NbdIoError::Connect)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(NbdIoError::Connect)?;
    let fd = OwnedFd::from(stream);
    let raw = fd.as_raw_fd();
    let handshake = NbdIoError::Handshake;

    let mut greeting = [0u8; 18];
    read_full(raw, &mut greeting).map_err(handshake)?;
    let magic = u64::from_be_bytes(greeting[..8].try_into().unwrap());
    let opt_magic = u64::from_be_bytes(greeting[8..16].try_into().unwrap());
    let server_flags = u16::from_be_bytes(greeting[16..].try_into().unwrap());
    if magic != NBD_MAGIC || opt_magic != IHAVEOPT {
        return Err(NbdIoError::Protocol("not a newstyle NBD server"));
    }
    if server_flags & FLAG_FIXED_NEWSTYLE == 0 {
        return Err(NbdIoError::Protocol(
            "the server does not do fixed newstyle",
        ));
    }
    let client_flags = u32::from(server_flags & (FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES));
    write_full(raw, &client_flags.to_be_bytes()).map_err(handshake)?;

    let name = config.export_name.as_bytes();
    let name_len =
        u32::try_from(name.len()).map_err(|_| NbdIoError::Protocol("export name too long"))?;
    let mut option = Vec::with_capacity(16 + 6 + name.len());
    option.extend_from_slice(&IHAVEOPT.to_be_bytes());
    option.extend_from_slice(&OPT_GO.to_be_bytes());
    option.extend_from_slice(&(name_len + 6).to_be_bytes());
    option.extend_from_slice(&name_len.to_be_bytes());
    option.extend_from_slice(name);
    // No information requests: the server sends the export's size and flags regardless.
    option.extend_from_slice(&0u16.to_be_bytes());
    write_full(raw, &option).map_err(handshake)?;

    let mut export = None;
    loop {
        let mut header = [0u8; 20];
        read_full(raw, &mut header).map_err(handshake)?;
        if u64::from_be_bytes(header[..8].try_into().unwrap()) != OPT_REPLY_MAGIC {
            return Err(NbdIoError::Protocol("bad option reply magic"));
        }
        let reply_type = u32::from_be_bytes(header[12..16].try_into().unwrap());
        let len = u32::from_be_bytes(header[16..].try_into().unwrap());
        if len > 64 * 1024 {
            return Err(NbdIoError::Protocol("option reply too long"));
        }
        let mut body = vec![0u8; len as usize];
        read_full(raw, &mut body).map_err(handshake)?;
        if reply_type & REP_ERR_BIT != 0 {
            return Err(NbdIoError::Refused(
                reply_type,
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
        match reply_type {
            REP_INFO if body.len() >= 12 && body[..2] == INFO_EXPORT.to_be_bytes() => {
                let size = u64::from_be_bytes(body[2..10].try_into().unwrap());
                let flags = u16::from_be_bytes(body[10..12].try_into().unwrap());
                export = Some((size, flags));
            }
            REP_ACK => break,
            _ => {}
        }
    }
    let (size, flags) = export.ok_or(NbdIoError::Protocol("the server sent no export size"))?;
    if size % (1 << SECTOR_SHIFT) != 0 {
        return Err(NbdIoError::Size(size));
    }
    set_nonblocking(raw).map_err(NbdIoError::Connect)?;
    Ok(Connection { fd, size, flags })
}

/// Connect, retrying until `timeout` has passed: the server may not be listening yet, or may
/// still hold the export for a connection that just went away.
fn connect_retrying(
    config: &NbdBackendConfig,
    timeout: Duration,
) -> Result<Connection, NbdIoError> {
    let deadline = Instant::now() + timeout;
    let mut delay = RECONNECT_DELAY_MIN;
    loop {
        match connect(config, HANDSHAKE_TIMEOUT) {
            Ok(connection) => return Ok(connection),
            Err(err) if Instant::now() + delay >= deadline => return Err(err),
            Err(_) => {
                thread::sleep(delay);
                delay = (delay * 2).min(RECONNECT_DELAY_MAX);
            }
        }
    }
}

/// Copy `data` into the guest buffers `segments`, from `offset` bytes into them on.
fn copy_to_segments(
    mem: &GuestMemoryMmap,
    segments: &[Segment],
    mut offset: u32,
    mut data: &[u8],
) -> Result<(), GuestMemoryError> {
    for &(addr, len) in segments {
        if data.is_empty() {
            break;
        }
        if offset >= len {
            offset -= len;
            continue;
        }
        let n = (len - offset).min(u32::try_from(data.len()).unwrap_or(u32::MAX));
        let addr = addr
            .checked_add(u64::from(offset))
            .ok_or(GuestMemoryError::GuestAddressOverflow)?;
        mem.write_slice(&data[..n as usize], addr)?;
        data = &data[n as usize..];
        offset = 0;
    }
    Ok(())
}

/// Append iovecs for the guest buffers `segments`, from `offset` bytes into them on, to `out`,
/// as long as it has room.
fn segment_iovecs(
    mem: &GuestMemoryMmap,
    segments: &[Segment],
    mut offset: u32,
    out: &mut Vec<libc::iovec>,
) -> Result<(), GuestMemoryError> {
    for &(addr, len) in segments {
        if out.len() >= MAX_IOVECS {
            break;
        }
        if offset >= len {
            offset -= len;
            continue;
        }
        let addr = addr
            .checked_add(u64::from(offset))
            .ok_or(GuestMemoryError::GuestAddressOverflow)?;
        let len = (len - offset) as usize;
        let slice = mem.get_slice(addr, len)?;
        out.push(libc::iovec {
            iov_base: slice.ptr_guard_mut().as_ptr().cast(),
            iov_len: len,
        });
        offset = 0;
    }
    Ok(())
}

/// A request sent, or to be sent, to the server.
#[derive(Debug)]
struct Slot {
    header: [u8; REQUEST_HEADER_LEN],
    command: u16,
    length: u32,
    /// The guest buffers a write's data comes from, or a read's goes to.
    segments: Vec<Segment>,
    /// Submission order, to send requests again in it after a reconnect.
    seq: u64,
    /// Completes the guest's request. None for the worker's own flush.
    pending: Option<PendingRequest>,
    /// For a flush, the writes completed when it was submitted, which it makes durable.
    write_epoch: u64,
}

impl Slot {
    fn new(cookie: usize, command: u16, offset: u64, length: u32, seq: u64) -> Self {
        let mut header = [0u8; REQUEST_HEADER_LEN];
        header[..4].copy_from_slice(&REQUEST_MAGIC.to_be_bytes());
        header[6..8].copy_from_slice(&command.to_be_bytes());
        header[8..16].copy_from_slice(&(cookie as u64).to_be_bytes());
        header[16..24].copy_from_slice(&offset.to_be_bytes());
        header[24..].copy_from_slice(&length.to_be_bytes());
        Slot {
            header,
            command,
            length,
            segments: Vec::new(),
            seq,
            pending: None,
            write_epoch: 0,
        }
    }

    /// Bytes this request takes on the wire.
    fn wire_len(&self) -> usize {
        REQUEST_HEADER_LEN
            + match self.command {
                CMD_WRITE => self.length as usize,
                _ => 0,
            }
    }
}

#[derive(Debug)]
enum Control {
    Start(Box<Serving>, Arc<Mutex<RateLimiter>>),
    Stop(Instant),
    Kick,
    Exit,
}

#[derive(Debug)]
enum Reply {
    Stopped(Result<Option<Queue>, NbdIoError>),
}

// Epoll tokens.
const CONTROL: u64 = 0;
const QUEUE: u64 = 1;
const RATE_LIMITER: u64 = 2;
const SOCKET: u64 = 3;

/// The worker's state while it serves the queue.
#[derive(Debug)]
struct Active {
    queue: Queue,
    queue_evt: std::mem::ManuallyDrop<EventFd>,
    mem: GuestMemoryMmap,
    interrupt: Arc<dyn VirtioInterrupt>,
    rate_limiter: Arc<Mutex<RateLimiter>>,
    rate_limiter_fd: RawFd,
    metrics: Arc<BlockDeviceMetrics>,
    nsectors: u64,
    image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
    segmented: bool,
    /// Completions added to the used ring and not yet published to the guest.
    used: bool,
}

/// A stop in progress: no more requests are taken off the queue, and the worker waits for those
/// in flight and a flush.
#[derive(Debug)]
struct Stopping {
    deadline: Instant,
    flush_sent: bool,
}

#[derive(Debug)]
struct Worker {
    config: NbdBackendConfig,
    epoll: Epoll,
    control_evt: EventFd,
    control: mpsc::Receiver<Control>,
    replies: mpsc::Sender<Reply>,
    active: Option<Active>,

    conn: Option<OwnedFd>,
    size: u64,
    flags: u16,
    /// Whether the socket is watched for room to write.
    watching_out: bool,
    reconnect_at: Option<Instant>,
    reconnect_delay: Duration,
    reconnect_attempts: u64,
    disconnected_at: Option<Instant>,

    slots: Vec<Option<Slot>>,
    in_flight: usize,
    next_seq: u64,
    /// Slots to send, in order, and how much of the first one is sent.
    send_queue: VecDeque<usize>,
    send_offset: usize,
    recv_buf: Vec<u8>,
    recv_start: usize,
    recv_end: usize,
    /// A read whose data is arriving: its slot and how much has.
    recv_data: Option<(usize, u32)>,

    /// Writes completed, and the most of them a completed flush covers.
    write_epoch: u64,
    flushed_epoch: u64,
    stopping: Option<Stopping>,
    flush_result: Option<Result<(), NbdIoError>>,
}

impl Worker {
    fn new(
        config: NbdBackendConfig,
        size: u64,
        flags: u16,
        epoll: Epoll,
        control_evt: EventFd,
        control: mpsc::Receiver<Control>,
        replies: mpsc::Sender<Reply>,
    ) -> Self {
        let mut slots = Vec::with_capacity(NUM_SLOTS);
        slots.resize_with(NUM_SLOTS, || None);
        Worker {
            config,
            epoll,
            control_evt,
            control,
            replies,
            active: None,
            conn: None,
            size,
            flags,
            watching_out: false,
            reconnect_at: None,
            reconnect_delay: RECONNECT_DELAY_MIN,
            reconnect_attempts: 0,
            disconnected_at: None,
            slots,
            in_flight: 0,
            next_seq: 0,
            send_queue: VecDeque::new(),
            send_offset: 0,
            recv_buf: vec![0u8; RECV_BUFFER_LEN],
            recv_start: 0,
            recv_end: 0,
            recv_data: None,
            write_epoch: 0,
            flushed_epoch: 0,
            stopping: None,
            flush_result: None,
        }
    }

    fn run(mut self, conn: OwnedFd) {
        if let Some(filter) = worker_seccomp_filter()
            && let Err(err) = crate::seccomp::apply_filter(filter)
        {
            panic!("Failed to set the requested seccomp filters on the NBD block worker: {err}");
        }
        self.attach(conn);

        let mut events = [EpollEvent::default(); 8];
        loop {
            let count = match self.epoll.wait(self.timeout_ms(), &mut events) {
                Ok(count) => count,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    error!("NBD block worker failed to wait for events: {:?}", err);
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
                    SOCKET => {
                        let set = event.event_set();
                        if set.intersects(EventSet::IN | EventSet::HANG_UP | EventSet::ERROR) {
                            self.receive();
                        }
                        if set.contains(EventSet::OUT) {
                            self.send();
                        }
                        if set.intersects(EventSet::HANG_UP | EventSet::ERROR)
                            && self.conn.is_some()
                        {
                            self.disconnect("the server hung up");
                        }
                    }
                    _ => {}
                }
            }
            self.tick();
        }
    }

    /// Milliseconds until the next reconnection attempt or stop deadline, or -1 for none.
    fn timeout_ms(&self) -> i32 {
        let next = [
            self.reconnect_at,
            self.stopping.as_ref().map(|stopping| stopping.deadline),
        ]
        .into_iter()
        .flatten()
        .min();
        match next {
            None => -1,
            Some(at) => {
                let wait = at.saturating_duration_since(Instant::now());
                i32::try_from(wait.as_micros().div_ceil(1000)).unwrap_or(i32::MAX)
            }
        }
    }

    /// Work that follows the events of one wait.
    fn tick(&mut self) {
        if self.reconnect_at.is_some_and(|at| at <= Instant::now()) {
            self.reconnect();
        }
        self.progress_stop();
        self.publish_used();
    }

    /// Handle a control message. Returns false when the worker has to exit.
    fn handle(&mut self, control: Control) -> bool {
        match control {
            Control::Start(serving, rate_limiter) => self.start(*serving, rate_limiter),
            Control::Stop(deadline) => {
                if self.active.is_none() {
                    let _ = self.replies.send(Reply::Stopped(Ok(None)));
                } else {
                    self.stopping = Some(Stopping {
                        deadline,
                        flush_sent: false,
                    });
                }
            }
            Control::Kick => self.process_queue(),
            Control::Exit => return false,
        }
        true
    }

    fn start(&mut self, serving: Serving, rate_limiter: Arc<Mutex<RateLimiter>>) {
        let mut name = format!("{THREAD_NAME_PREFIX}{}", serving.drive_id).into_bytes();
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
                error!("NBD block worker failed to watch fd {}: {:?}", fd, err);
            }
        }
        self.active = Some(Active {
            queue: serving.queue,
            // SAFETY: the fd is the device's, which keeps it open until it has stopped the
            // worker. `ManuallyDrop` keeps the worker from closing it.
            queue_evt: std::mem::ManuallyDrop::new(unsafe {
                EventFd::from_raw_fd(serving.queue_evt)
            }),
            mem: serving.mem,
            interrupt: serving.interrupt,
            rate_limiter,
            rate_limiter_fd,
            metrics: serving.metrics,
            nsectors: serving.nsectors,
            image_id: serving.image_id,
            segmented: serving.segmented,
            used: false,
        });
        self.process_queue();
        self.publish_used();
        // Interrupt the guest whether or not that completed anything: an interrupt lost across
        // a snapshot would otherwise leave a guest using VIRTIO_RING_F_EVENT_IDX waiting for
        // completions it already has. A spurious interrupt is harmless.
        if let Some(active) = self.active.as_ref() {
            active
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| active.metrics.event_fails.inc());
        }
    }

    /// Stop serving the queue, and return it. Nothing may be in flight.
    fn stop_serving(&mut self) -> Option<Queue> {
        let active = self.active.take()?;
        for fd in [active.queue_evt.as_raw_fd(), active.rate_limiter_fd] {
            let _ = self
                .epoll
                .ctl(ControlOperation::Delete, fd, EpollEvent::default());
        }
        Some(active.queue)
    }

    /// Move a stop along: once nothing is in flight, flush; once flushed, hand the queue back.
    /// Past its deadline, give up and carry on serving.
    fn progress_stop(&mut self) {
        let Some(stopping) = self.stopping.as_mut() else {
            return;
        };
        if self.in_flight == 0 {
            let needs_flush = self.flags & TFLAG_SEND_FLUSH != 0
                && self.flags & TFLAG_READ_ONLY == 0
                && self.write_epoch > self.flushed_epoch;
            let done = if !stopping.flush_sent && needs_flush {
                stopping.flush_sent = true;
                self.flush_result = None;
                self.submit_flush();
                None
            } else if stopping.flush_sent {
                self.flush_result.take()
            } else {
                Some(Ok(()))
            };
            match done {
                Some(Ok(())) => {
                    self.stopping = None;
                    let queue = self.stop_serving();
                    let _ = self.replies.send(Reply::Stopped(Ok(queue)));
                    return;
                }
                Some(Err(err)) => {
                    // The server failed the flush. Don't hand back a queue whose writes may not
                    // be durable; carry on serving.
                    self.stopping = None;
                    let _ = self.replies.send(Reply::Stopped(Err(err)));
                    self.process_queue();
                    return;
                }
                None => {}
            }
        }
        if self
            .stopping
            .as_ref()
            .is_some_and(|stopping| stopping.deadline <= Instant::now())
        {
            warn!(
                "NBD block worker: {} requests still in flight at the stop deadline",
                self.in_flight
            );
            self.stopping = None;
            let _ = self
                .replies
                .send(Reply::Stopped(Err(NbdIoError::StopTimeout)));
            self.process_queue();
        }
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

    /// Take every request available off the queue, until it is empty or the rate limiter blocks,
    /// and send them.
    fn process_queue(&mut self) {
        if self.stopping.is_some() {
            return;
        }
        let Some(active) = self.active.as_mut() else {
            return;
        };
        let mut popped_any = false;
        loop {
            let head = match active.queue.pop_or_enable_notification() {
                Ok(Some(head)) => head,
                Ok(None) => break,
                Err(err) => panic!("Block queue is corrupt: {err}"),
            };
            popped_any = true;
            active
                .metrics
                .remaining_reqs_count
                .add(active.queue.len().into());

            let request =
                match Request::parse_any(&head, &active.mem, active.nsectors, active.segmented) {
                    Ok(request) => request,
                    Err(err) => {
                        error!("Failed to parse available descriptor chain: {:?}", err);
                        active.metrics.execute_fails.inc();
                        Self::add_used(active, head.index, 0);
                        continue;
                    }
                };
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

            let index = usize::from(head.index);
            if self.slots[index].is_some() {
                error!("Descriptor head {} is already in flight", head.index);
                active.metrics.execute_fails.inc();
                Self::add_used(active, head.index, 0);
                continue;
            }
            let pending = request.to_pending_request(head.index);
            let command = match request.r#type {
                RequestType::In => CMD_READ,
                RequestType::Out => CMD_WRITE,
                RequestType::Flush if self.flags & TFLAG_SEND_FLUSH != 0 => CMD_FLUSH,
                // The server keeps nothing to flush.
                RequestType::Flush => {
                    let finished = pending.finish(&active.mem, Ok(0), &active.metrics);
                    Self::add_used(active, finished.desc_idx, finished.num_bytes_to_mem);
                    continue;
                }
                RequestType::GetDeviceID => {
                    let result = active
                        .mem
                        .write_slice(&active.image_id, request.data_addr)
                        .map(|_| VIRTIO_BLK_ID_BYTES)
                        .map_err(IoErr::GetId);
                    let finished = pending.finish(&active.mem, result, &active.metrics);
                    Self::add_used(active, finished.desc_idx, finished.num_bytes_to_mem);
                    continue;
                }
                RequestType::Unsupported(_) => {
                    let finished = pending.finish(&active.mem, Ok(0), &active.metrics);
                    Self::add_used(active, finished.desc_idx, finished.num_bytes_to_mem);
                    continue;
                }
            };

            let (offset, length) = match command {
                CMD_FLUSH => (0, 0),
                _ => (request.sector << SECTOR_SHIFT, request.data_len),
            };
            let mut slot = Slot::new(index, command, offset, length, self.next_seq);
            self.next_seq += 1;
            if command != CMD_FLUSH {
                slot.segments = if request.segments.is_empty() {
                    vec![(request.data_addr, request.data_len)]
                } else {
                    request.segments.clone()
                };
                // Check the buffers now, rather than fail a request half sent.
                if let Some(err) = slot
                    .segments
                    .iter()
                    .find_map(|&(addr, len)| active.mem.get_slice(addr, len as usize).err())
                {
                    let result = Err(IoErr::FileEngine(BlockIoError::Nbd(
                        NbdIoError::GuestMemory(err),
                    )));
                    let finished = pending.finish(&active.mem, result, &active.metrics);
                    Self::add_used(active, finished.desc_idx, finished.num_bytes_to_mem);
                    continue;
                }
            } else {
                slot.write_epoch = self.write_epoch;
            }
            slot.pending = Some(pending);
            self.slots[index] = Some(slot);
            self.in_flight += 1;
            self.send_queue.push_back(index);
        }
        if !popped_any {
            active.metrics.no_avail_buffer.inc();
        }
        self.send();
    }

    fn add_used(active: &mut Active, desc_idx: u16, len: u32) {
        active.queue.add_used(desc_idx, len).unwrap_or_else(|err| {
            error!(
                "Failed to add available descriptor head {}: {}",
                desc_idx, err
            )
        });
        active.used = true;
    }

    /// Publish completions to the guest, and interrupt it if it wants to know.
    fn publish_used(&mut self) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if !active.used {
            return;
        }
        active.used = false;
        active.queue.advance_used_ring_idx();
        if active.queue.prepare_kick() {
            active
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| active.metrics.event_fails.inc());
        }
    }

    /// Have the server flush, for a stop.
    fn submit_flush(&mut self) {
        let mut slot = Slot::new(FLUSH_SLOT, CMD_FLUSH, 0, 0, self.next_seq);
        self.next_seq += 1;
        slot.write_epoch = self.write_epoch;
        self.slots[FLUSH_SLOT] = Some(slot);
        self.in_flight += 1;
        self.send_queue.push_back(FLUSH_SLOT);
        self.send();
    }

    /// Complete a request with the server's answer.
    fn complete(&mut self, index: usize, result: Result<(), NbdIoError>) {
        let Some(slot) = self.slots[index].take() else {
            return;
        };
        self.in_flight -= 1;
        // A request the server did is done whole.
        let result = result.map(|_| slot.length);
        match slot.command {
            CMD_WRITE if result.is_ok() => self.write_epoch += 1,
            CMD_FLUSH if result.is_ok() => {
                self.flushed_epoch = self.flushed_epoch.max(slot.write_epoch)
            }
            _ => {}
        }
        let Some(pending) = slot.pending else {
            self.flush_result = Some(result.map(|_| ()));
            return;
        };
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if slot.command == CMD_READ && result.is_ok() {
            // The guest memory was written from this thread, so account for it in the dirty
            // bitmap before the guest gets to see the completion.
            for &(addr, len) in &slot.segments {
                active.mem.mark_dirty(addr, len as usize);
            }
        }
        let result = result.map_err(|err| IoErr::FileEngine(BlockIoError::Nbd(err)));
        let finished = pending.finish(&active.mem, result, &active.metrics);
        Self::add_used(active, finished.desc_idx, finished.num_bytes_to_mem);
    }

    /// Send as much of the send queue as the socket takes.
    fn send(&mut self) {
        let Some(fd) = self.conn.as_ref().map(|fd| fd.as_raw_fd()) else {
            return;
        };
        let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(64);
        while !self.send_queue.is_empty() {
            iovecs.clear();
            let mut skip = self.send_offset;
            for &index in &self.send_queue {
                if iovecs.len() + 1 >= MAX_IOVECS {
                    break;
                }
                let slot = self.slots[index].as_ref().expect("queued slot is empty");
                if skip < REQUEST_HEADER_LEN {
                    iovecs.push(libc::iovec {
                        iov_base: slot.header[skip..].as_ptr() as *mut libc::c_void,
                        iov_len: REQUEST_HEADER_LEN - skip,
                    });
                    skip = 0;
                } else {
                    skip -= REQUEST_HEADER_LEN;
                }
                if slot.command == CMD_WRITE {
                    let mem = &self
                        .active
                        .as_ref()
                        .expect("a write without guest memory")
                        .mem;
                    let offset = u32::try_from(skip).expect("offset within a request");
                    if let Err(err) = segment_iovecs(mem, &slot.segments, offset, &mut iovecs) {
                        // Checked when the request was taken off the queue.
                        panic!("Guest buffer of a request in flight is gone: {err}");
                    }
                }
                skip = 0;
            }
            let iovcnt = libc::c_int::try_from(iovecs.len()).unwrap_or(libc::c_int::MAX);
            // SAFETY: each iovec points into a slot's header, which outlives the call, or into
            // guest memory that `mem` keeps mapped, within the bounds `get_slice` checked.
            let ret = unsafe { libc::writev(fd, iovecs.as_ptr(), iovcnt) };
            let mut sent = match usize::try_from(ret) {
                Ok(sent) => sent,
                Err(_) => {
                    let err = io::Error::last_os_error();
                    match err.kind() {
                        io::ErrorKind::Interrupted => continue,
                        _ if would_block(&err) => {
                            self.watch_out(true);
                            return;
                        }
                        _ => {
                            self.disconnect(&format!("sending: {err}"));
                            return;
                        }
                    }
                }
            };
            while let Some(&index) = self.send_queue.front() {
                let left = self.slots[index].as_ref().unwrap().wire_len() - self.send_offset;
                if sent < left {
                    self.send_offset += sent;
                    break;
                }
                sent -= left;
                self.send_offset = 0;
                self.send_queue.pop_front();
            }
        }
        self.watch_out(false);
    }

    fn watch_out(&mut self, on: bool) {
        if self.watching_out == on {
            return;
        }
        let Some(fd) = self.conn.as_ref().map(|fd| fd.as_raw_fd()) else {
            return;
        };
        let mut set = EventSet::IN | EventSet::HANG_UP | EventSet::ERROR;
        if on {
            set |= EventSet::OUT;
        }
        if let Err(err) = self
            .epoll
            .ctl(ControlOperation::Modify, fd, EpollEvent::new(set, SOCKET))
        {
            error!("NBD block worker failed to watch its socket: {:?}", err);
        }
        self.watching_out = on;
    }

    /// Read and complete every answer the socket holds.
    fn receive(&mut self) {
        loop {
            let Some(fd) = self.conn.as_ref().map(|fd| fd.as_raw_fd()) else {
                return;
            };
            if let Some((index, done)) = self.recv_data {
                let slot = self.slots[index]
                    .as_ref()
                    .expect("reading into an empty slot");
                let mem = &self
                    .active
                    .as_ref()
                    .expect("a read without guest memory")
                    .mem;
                let length = slot.length;
                let buffered = self.recv_end - self.recv_start;
                let got = if buffered > 0 {
                    let n = buffered.min((length - done) as usize);
                    let data = &self.recv_buf[self.recv_start..self.recv_start + n];
                    if let Err(err) = copy_to_segments(mem, &slot.segments, done, data) {
                        panic!("Guest buffer of a request in flight is gone: {err}");
                    }
                    self.recv_start += n;
                    n
                } else {
                    let mut iovecs = Vec::with_capacity(slot.segments.len());
                    if let Err(err) = segment_iovecs(mem, &slot.segments, done, &mut iovecs) {
                        panic!("Guest buffer of a request in flight is gone: {err}");
                    }
                    let iovcnt = libc::c_int::try_from(iovecs.len()).unwrap_or(libc::c_int::MAX);
                    // SAFETY: the iovecs point into guest memory that `mem` keeps mapped,
                    // within the bounds `get_slice` checked.
                    let ret = unsafe { libc::readv(fd, iovecs.as_ptr(), iovcnt) };
                    match usize::try_from(ret) {
                        Ok(0) => {
                            self.disconnect("the server closed the connection");
                            return;
                        }
                        Ok(n) => n,
                        Err(_) => {
                            let err = io::Error::last_os_error();
                            match err.kind() {
                                io::ErrorKind::Interrupted => continue,
                                _ if would_block(&err) => return,
                                _ => {
                                    self.disconnect(&format!("receiving: {err}"));
                                    return;
                                }
                            }
                        }
                    }
                };
                let done = done + u32::try_from(got).expect("bounded by a request's length");
                if done == length {
                    self.recv_data = None;
                    self.complete(index, Ok(()));
                } else {
                    self.recv_data = Some((index, done));
                }
                continue;
            }

            if self.recv_end - self.recv_start < REPLY_HEADER_LEN {
                if self.recv_start > 0 {
                    self.recv_buf.copy_within(self.recv_start..self.recv_end, 0);
                    self.recv_end -= self.recv_start;
                    self.recv_start = 0;
                }
                let buf = &mut self.recv_buf[self.recv_end..];
                // SAFETY: `buf` is valid for writes of its length.
                let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                match usize::try_from(ret) {
                    Ok(0) => {
                        self.disconnect("the server closed the connection");
                        return;
                    }
                    Ok(n) => self.recv_end += n,
                    Err(_) => {
                        let err = io::Error::last_os_error();
                        match err.kind() {
                            io::ErrorKind::Interrupted => {}
                            _ if would_block(&err) => return,
                            _ => {
                                self.disconnect(&format!("receiving: {err}"));
                                return;
                            }
                        }
                    }
                }
                continue;
            }

            let header = &self.recv_buf[self.recv_start..self.recv_start + REPLY_HEADER_LEN];
            let magic = u32::from_be_bytes(header[..4].try_into().unwrap());
            let errno = u32::from_be_bytes(header[4..8].try_into().unwrap());
            let cookie = u64::from_be_bytes(header[8..].try_into().unwrap());
            self.recv_start += REPLY_HEADER_LEN;
            if magic != SIMPLE_REPLY_MAGIC {
                self.disconnect("bad reply magic");
                return;
            }
            let index = usize::try_from(cookie).unwrap_or(usize::MAX);
            let Some(command) = self
                .slots
                .get(index)
                .and_then(Option::as_ref)
                .map(|s| s.command)
            else {
                self.disconnect("a reply to no request in flight");
                return;
            };
            if self.send_queue.contains(&index) {
                self.disconnect("a reply to a request not sent");
                return;
            }
            match errno {
                0 if command == CMD_READ => self.recv_data = Some((index, 0)),
                0 => self.complete(index, Ok(())),
                NBD_ESHUTDOWN => {
                    // Not done: send it again once the server is back.
                    self.disconnect("the server is shutting down");
                    return;
                }
                errno => self.complete(index, Err(NbdIoError::Server(errno))),
            }
        }
    }

    /// Drop the connection, queue every request in flight to be sent again, and reconnect.
    fn disconnect(&mut self, why: &str) {
        let Some(fd) = self.conn.take() else {
            return;
        };
        let _ = self.epoll.ctl(
            ControlOperation::Delete,
            fd.as_raw_fd(),
            EpollEvent::default(),
        );
        drop(fd);
        self.watching_out = false;
        warn!(
            "NBD connection to {} lost, with {} requests in flight: {}",
            self.config.socket_path, self.in_flight, why
        );
        self.recv_data = None;
        self.recv_start = 0;
        self.recv_end = 0;
        self.send_offset = 0;
        let mut in_flight: Vec<(u64, usize)> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.as_ref().map(|slot| (slot.seq, index)))
            .collect();
        in_flight.sort_unstable();
        self.send_queue = in_flight.into_iter().map(|(_, index)| index).collect();
        self.disconnected_at = Some(Instant::now());
        self.reconnect_attempts = 0;
        self.reconnect_delay = RECONNECT_DELAY_MIN;
        self.reconnect_at = Some(Instant::now());
    }

    /// Try to connect again, and send what is queued if that works.
    fn reconnect(&mut self) {
        self.reconnect_attempts += 1;
        match connect(&self.config, HANDSHAKE_TIMEOUT) {
            Ok(conn) => {
                if conn.size != self.size {
                    error!(
                        "NBD export {} changed size from {} to {} bytes",
                        self.config.export_name, self.size, conn.size
                    );
                }
                self.flags = conn.flags;
                let waited = self
                    .disconnected_at
                    .take()
                    .map(|at| at.elapsed())
                    .unwrap_or_default();
                info!(
                    "NBD connection to {} back after {} attempts and {:?}; resending {} requests",
                    self.config.socket_path,
                    self.reconnect_attempts,
                    waited,
                    self.send_queue.len()
                );
                self.reconnect_at = None;
                self.attach(conn.fd);
                self.send();
            }
            Err(err) => {
                if self.reconnect_attempts == 1 || self.reconnect_attempts % 100 == 0 {
                    warn!(
                        "NBD reconnection to {} failed, attempt {}: {}",
                        self.config.socket_path, self.reconnect_attempts, err
                    );
                }
                self.reconnect_at = Some(Instant::now() + self.reconnect_delay);
                self.reconnect_delay = (self.reconnect_delay * 2).min(RECONNECT_DELAY_MAX);
            }
        }
    }

    fn attach(&mut self, fd: OwnedFd) {
        if let Err(err) = self.epoll.ctl(
            ControlOperation::Add,
            fd.as_raw_fd(),
            EpollEvent::new(EventSet::IN | EventSet::HANG_UP | EventSet::ERROR, SOCKET),
        ) {
            error!("NBD block worker failed to watch its socket: {:?}", err);
        }
        self.watching_out = false;
        self.conn = Some(fd);
    }
}

/// Front end of the NBD engine, used from the thread that owns the device.
#[derive(Debug)]
pub struct NbdFileEngine {
    config: NbdBackendConfig,
    size: u64,
    read_only: bool,
    control: mpsc::Sender<Control>,
    control_evt: EventFd,
    replies: mpsc::Receiver<Reply>,
    // While the worker serves the queue: the rate limiter it shares with the device.
    rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
    // Takes the device's rate limiter's place while the worker has it.
    spare_rate_limiter: Option<RateLimiter>,
    worker: Option<thread::JoinHandle<()>>,
}

impl NbdFileEngine {
    /// Connect to the server, waiting a while for it if need be, and start the worker.
    pub fn connect(config: NbdBackendConfig) -> Result<NbdFileEngine, NbdIoError> {
        Self::connect_with_timeout(config, INITIAL_CONNECT_TIMEOUT)
    }

    pub fn connect_with_timeout(
        config: NbdBackendConfig,
        timeout: Duration,
    ) -> Result<NbdFileEngine, NbdIoError> {
        let conn = connect_retrying(&config, timeout)?;
        let (size, read_only) = (conn.size, conn.flags & TFLAG_READ_ONLY != 0);
        let control_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(NbdIoError::EventFd)?;
        let worker_control_evt = control_evt.try_clone().map_err(NbdIoError::EventFd)?;
        // Before the worker applies its seccomp filter, which does not allow creating it.
        let epoll = Epoll::new().map_err(NbdIoError::Epoll)?;
        epoll
            .ctl(
                ControlOperation::Add,
                worker_control_evt.as_raw_fd(),
                EpollEvent::new(EventSet::IN, CONTROL),
            )
            .map_err(NbdIoError::Epoll)?;
        let (control, worker_control) = mpsc::channel();
        let (worker_replies, replies) = mpsc::channel();
        let fd = conn.fd;
        let worker = Worker::new(
            config.clone(),
            conn.size,
            conn.flags,
            epoll,
            worker_control_evt,
            worker_control,
            worker_replies,
        );
        let worker = thread::Builder::new()
            .name("fc_blk_nbd".to_string())
            .spawn(move || worker.run(fd))
            .map_err(NbdIoError::Spawn)?;

        Ok(NbdFileEngine {
            config,
            size,
            read_only,
            control,
            control_evt,
            replies,
            rate_limiter: None,
            spare_rate_limiter: Some(RateLimiter::default()),
            worker: Some(worker),
        })
    }

    /// The export's size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether the server offers the export read-only.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub fn config(&self) -> &NbdBackendConfig {
        &self.config
    }

    fn send(&self, control: Control) -> Result<(), NbdIoError> {
        self.control
            .send(control)
            .map_err(|_| NbdIoError::WorkerGone)?;
        self.control_evt.write(1).map_err(NbdIoError::EventFd)
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
    ) -> Result<(), NbdIoError> {
        let Some(mut spare) = self.spare_rate_limiter.take() else {
            return Ok(());
        };
        std::mem::swap(device_rate_limiter, &mut spare);
        let rate_limiter = Arc::new(Mutex::new(spare));
        self.send(Control::Start(Box::new(serving), rate_limiter.clone()))?;
        self.rate_limiter = Some(rate_limiter);
        Ok(())
    }

    /// Have the worker stop taking requests, wait for those in flight, have the server flush,
    /// and hand the queue back, with the rate limiter. Should that not finish within `timeout`,
    /// or the flush fail, the worker carries on serving the queue and this fails.
    pub fn stop_within(
        &mut self,
        device_rate_limiter: &mut RateLimiter,
        timeout: Duration,
    ) -> Result<Option<Queue>, NbdIoError> {
        if self.rate_limiter.is_none() {
            return Ok(None);
        }
        self.send(Control::Stop(Instant::now() + timeout))?;
        let Reply::Stopped(result) = self.replies.recv().map_err(|_| NbdIoError::WorkerGone)?;
        let queue = result?;
        // The worker dropped its reference before replying.
        let rate_limiter = self.rate_limiter.take().expect("checked above");
        let mut rate_limiter = Arc::try_unwrap(rate_limiter)
            .expect("NBD block worker kept the rate limiter")
            .into_inner()
            .expect("Poisoned block rate limiter lock");
        std::mem::swap(device_rate_limiter, &mut rate_limiter);
        self.spare_rate_limiter = Some(rate_limiter);
        Ok(queue)
    }

    pub fn stop(
        &mut self,
        device_rate_limiter: &mut RateLimiter,
    ) -> Result<Option<Queue>, NbdIoError> {
        self.stop_within(device_rate_limiter, NBD_STOP_TIMEOUT)
    }

    /// Have the worker look at the queue, as if the guest had notified it.
    pub fn kick(&self) -> Result<(), NbdIoError> {
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

    /// The export cannot be swapped for a file.
    pub fn update_file(&mut self, _file: File) -> Result<(), NbdIoError> {
        Err(NbdIoError::NoBackingFile)
    }

    /// Nothing to wait for: requests are in flight only while the worker serves the queue, and
    /// it waits for them when it stops.
    pub fn drain(&mut self, _discard: bool) -> Result<(), NbdIoError> {
        Ok(())
    }

    /// The flush happens when the worker stops serving the queue, see [`Self::stop`].
    pub fn drain_and_flush(&mut self, _discard: bool) -> Result<(), NbdIoError> {
        Ok(())
    }

    /// Requests are served by the worker, from the queue. Should one get here, it fails.
    pub fn refuse(req: PendingRequest) -> RequestError<NbdIoError> {
        RequestError {
            req,
            error: NbdIoError::ServedByWorker,
        }
    }
}

impl Drop for NbdFileEngine {
    fn drop(&mut self) {
        let _ = self.send(Control::Exit);
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            error!("The NBD block worker thread panicked");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use super::*;
    use crate::devices::virtio::block::virtio::nbd::test_server::TestServer;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::memory::GuestRegionMmapExt;

    fn create_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            memory::anonymous(
                [(GuestAddress(0), 0x10000)].into_iter(),
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

    #[test]
    fn test_handshake() {
        let server = TestServer::new(1 << 20);
        let conn = connect(&server.config(), HANDSHAKE_TIMEOUT).unwrap();
        assert_eq!(conn.size, 1 << 20);
        assert_ne!(conn.flags & TFLAG_SEND_FLUSH, 0);

        // The server allows one connection per export, as some do; a second is refused until
        // the first goes away.
        let err = connect(&server.config(), HANDSHAKE_TIMEOUT).unwrap_err();
        assert!(matches!(err, NbdIoError::Refused(_, _)), "{err:?}");
        drop(conn);
        connect_retrying(&server.config(), Duration::from_secs(5)).unwrap();

        // An unknown export, or no server at all.
        let mut config = server.config();
        config.export_name = "nope".to_string();
        assert!(matches!(
            connect(&config, HANDSHAKE_TIMEOUT),
            Err(NbdIoError::Refused(_, _))
        ));
        config.socket_path = "/nonexistent/nbd.sock".to_string();
        assert!(matches!(
            connect_retrying(&config, Duration::from_millis(50)),
            Err(NbdIoError::Connect(_))
        ));
    }

    #[test]
    fn test_segments() {
        let mem = create_mem();
        let segments = [
            (GuestAddress(0x1000), 512),
            (GuestAddress(0x4000), 1024),
            (GuestAddress(0x200), 512),
        ];
        let data: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
        // In two pieces, the second starting within the second buffer.
        copy_to_segments(&mem, &segments, 0, &data[..700]).unwrap();
        copy_to_segments(&mem, &segments, 700, &data[700..]).unwrap();
        let mut buf = vec![0u8; 2048];
        mem.read_slice(&mut buf[..512], GuestAddress(0x1000))
            .unwrap();
        mem.read_slice(&mut buf[512..1536], GuestAddress(0x4000))
            .unwrap();
        mem.read_slice(&mut buf[1536..], GuestAddress(0x200))
            .unwrap();
        assert_eq!(buf, data);

        let mut iovecs = Vec::new();
        segment_iovecs(&mem, &segments, 700, &mut iovecs).unwrap();
        assert_eq!(
            iovecs.iter().map(|iov| iov.iov_len).collect::<Vec<_>>(),
            vec![836, 512]
        );
        assert!(segment_iovecs(&mem, &[(GuestAddress(0x10000), 512)], 0, &mut iovecs).is_err());
    }

    #[test]
    fn test_slot_header() {
        let slot = Slot::new(7, CMD_WRITE, 0x1234_5600, 4096, 0);
        assert_eq!(slot.wire_len(), REQUEST_HEADER_LEN + 4096);
        assert_eq!(&slot.header[..4], &REQUEST_MAGIC.to_be_bytes());
        assert_eq!(&slot.header[6..8], &CMD_WRITE.to_be_bytes());
        assert_eq!(&slot.header[8..16], &7u64.to_be_bytes());
        assert_eq!(&slot.header[16..24], &0x1234_5600u64.to_be_bytes());
        assert_eq!(&slot.header[24..], &4096u32.to_be_bytes());
        assert_eq!(
            Slot::new(1, CMD_READ, 0, 4096, 0).wire_len(),
            REQUEST_HEADER_LEN
        );
    }
}
