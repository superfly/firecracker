// Copyright 2026 Fly.io, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tests of block devices served over NBD, and the NBD server they run against.

pub mod test_server {
    //! A small NBD server on a Unix socket, serving one export from memory. Like some servers,
    //! it allows one connection to the export at a time. Tests can have it answer requests out
    //! of order, hold its answers back, and drop the connection.

    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempdir::TempDir;

    use crate::devices::virtio::block::virtio::NbdBackendConfig;

    pub const EXPORT: &str = "test/export";

    #[derive(Debug, Default)]
    pub struct State {
        pub data: Mutex<Vec<u8>>,
        /// Flushes served.
        pub flushes: AtomicU64,
        /// Connections that got the export.
        pub connections: AtomicU64,
        /// Requests received, whole.
        pub requests: AtomicU64,
        /// Answer what arrives together in reverse order.
        pub reverse: AtomicBool,
        /// Hold answers back while set.
        pub stall: AtomicBool,
        /// Fail flushes with EIO.
        pub fail_flush: AtomicBool,
        claimed: AtomicBool,
        current: Mutex<Option<UnixStream>>,
    }

    #[derive(Debug)]
    pub struct TestServer {
        _dir: TempDir,
        path: String,
        pub state: Arc<State>,
    }

    impl TestServer {
        pub fn new(size: usize) -> Self {
            let dir = TempDir::new().unwrap();
            let path = dir.as_path().join("nbd.sock").to_str().unwrap().to_string();
            let listener = UnixListener::bind(&path).unwrap();
            let state = Arc::new(State {
                data: Mutex::new(vec![0u8; size]),
                ..Default::default()
            });
            let accept_state = state.clone();
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else {
                        return;
                    };
                    let state = accept_state.clone();
                    thread::spawn(move || serve(stream, state));
                }
            });
            TestServer {
                _dir: dir,
                path,
                state,
            }
        }

        pub fn config(&self) -> NbdBackendConfig {
            NbdBackendConfig {
                socket_path: self.path.clone(),
                export_name: EXPORT.to_string(),
            }
        }

        /// Drop the current connection, as a server that went away would.
        pub fn kill_connection(&self) {
            if let Some(stream) = self.state.current.lock().unwrap().take() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }

        pub fn data(&self, offset: usize, len: usize) -> Vec<u8> {
            self.state.data.lock().unwrap()[offset..offset + len].to_vec()
        }
    }

    fn read_u32(stream: &mut UnixStream) -> std::io::Result<u32> {
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn option_reply(stream: &mut UnixStream, option: u32, reply: u32, data: &[u8]) {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0003_e889_0455_65a9u64.to_be_bytes());
        buf.extend_from_slice(&option.to_be_bytes());
        buf.extend_from_slice(&reply.to_be_bytes());
        buf.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(data);
        let _ = stream.write_all(&buf);
    }

    /// Negotiate the export. Returns false if the connection is not to go on.
    fn handshake(stream: &mut UnixStream, state: &State) -> std::io::Result<bool> {
        let mut greeting = Vec::new();
        greeting.extend_from_slice(b"NBDMAGIC");
        greeting.extend_from_slice(b"IHAVEOPT");
        greeting.extend_from_slice(&1u16.to_be_bytes());
        stream.write_all(&greeting)?;
        let _client_flags = read_u32(stream)?;
        loop {
            let mut magic = [0u8; 8];
            stream.read_exact(&mut magic)?;
            let option = read_u32(stream)?;
            let len = read_u32(stream)?;
            let mut data = vec![0u8; len as usize];
            stream.read_exact(&mut data)?;
            if option != 7 {
                option_reply(stream, option, 0x8000_0001, &[]);
                continue;
            }
            let name_len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
            if &data[4..4 + name_len] != EXPORT.as_bytes() {
                option_reply(stream, option, 0x8000_0006, b"unknown export");
                continue;
            }
            if state.claimed.swap(true, Ordering::SeqCst) {
                option_reply(stream, option, 0x8000_0002, b"export in use");
                return Ok(false);
            }
            let size = state.data.lock().unwrap().len() as u64;
            let mut info = Vec::new();
            info.extend_from_slice(&0u16.to_be_bytes());
            info.extend_from_slice(&size.to_be_bytes());
            // HAS_FLAGS | SEND_FLUSH
            info.extend_from_slice(&5u16.to_be_bytes());
            option_reply(stream, option, 3, &info);
            option_reply(stream, option, 1, &[]);
            return Ok(true);
        }
    }

    struct Request {
        command: u16,
        cookie: u64,
        offset: usize,
        length: usize,
        payload: Vec<u8>,
    }

    fn serve(mut stream: UnixStream, state: Arc<State>) {
        match handshake(&mut stream, &state) {
            Ok(true) => {}
            _ => return,
        }
        state.connections.fetch_add(1, Ordering::SeqCst);
        *state.current.lock().unwrap() = Some(stream.try_clone().unwrap());
        let dead = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<Request>();
        let mut reader = stream.try_clone().unwrap();
        let reader_dead = dead.clone();
        let reader_state = state.clone();
        let reader_thread = thread::spawn(move || {
            loop {
                let mut header = [0u8; 28];
                if reader.read_exact(&mut header).is_err() {
                    break;
                }
                let command = u16::from_be_bytes(header[6..8].try_into().unwrap());
                let length = u32::from_be_bytes(header[24..].try_into().unwrap()) as usize;
                let mut payload = Vec::new();
                if command == 1 {
                    payload = vec![0u8; length];
                    if reader.read_exact(&mut payload).is_err() {
                        break;
                    }
                }
                if command == 2 {
                    break;
                }
                reader_state.requests.fetch_add(1, Ordering::SeqCst);
                let request = Request {
                    command,
                    cookie: u64::from_be_bytes(header[8..16].try_into().unwrap()),
                    offset: usize::try_from(u64::from_be_bytes(header[16..24].try_into().unwrap()))
                        .unwrap(),
                    length,
                    payload,
                };
                if tx.send(request).is_err() {
                    break;
                }
            }
            reader_dead.store(true, Ordering::SeqCst);
        });

        while let Ok(first) = rx.recv() {
            let mut batch = vec![first];
            if state.reverse.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(20));
                batch.extend(rx.try_iter());
                batch.reverse();
            }
            for request in batch {
                while state.stall.load(Ordering::SeqCst) && !dead.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
                if dead.load(Ordering::SeqCst) {
                    break;
                }
                let mut error = 0u32;
                let mut payload = Vec::new();
                {
                    let mut data = state.data.lock().unwrap();
                    let range = request.offset..request.offset + request.length;
                    match request.command {
                        0 => payload = data[range].to_vec(),
                        1 => data[range].copy_from_slice(&request.payload),
                        3 if state.fail_flush.load(Ordering::SeqCst) => error = 5,
                        3 => {
                            state.flushes.fetch_add(1, Ordering::SeqCst);
                        }
                        _ => error = 22,
                    }
                }
                let mut reply = Vec::new();
                reply.extend_from_slice(&0x6744_6698u32.to_be_bytes());
                reply.extend_from_slice(&error.to_be_bytes());
                reply.extend_from_slice(&request.cookie.to_be_bytes());
                if error == 0 {
                    reply.extend_from_slice(&payload);
                }
                if stream.write_all(&reply).is_err() {
                    break;
                }
            }
            if dead.load(Ordering::SeqCst) {
                break;
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
        let _ = reader_thread.join();
        state.claimed.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::test_server::{EXPORT, TestServer};
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::block::persist::BlockConstructorArgs;
    use crate::devices::virtio::block::virtio::device::{FileEngineType, VirtioBlockConfig};
    use crate::devices::virtio::block::virtio::io::{FileEngine, NbdFileEngine, NbdIoError};
    use crate::devices::virtio::block::virtio::test_utils::set_queue;
    use crate::devices::virtio::block::virtio::{
        RequestHeader, VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_IOERR, VIRTIO_BLK_S_OK,
        VIRTIO_BLK_T_FLUSH, VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, VirtioBlock,
    };
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::generated::virtio_blk::{VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_SEG_MAX};
    use crate::devices::virtio::queue::{
        FIRECRACKER_MAX_QUEUE_SIZE, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::devices::virtio::transport::VirtioInterruptType;
    use crate::rate_limiter::RateLimiter;
    use crate::snapshot::Persist;
    use crate::vmm_config::drive::BlockDeviceConfig;
    use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};

    const DISK_SIZE: usize = 1 << 20;

    fn nbd_block(server: &TestServer) -> VirtioBlock {
        VirtioBlock::new(VirtioBlockConfig {
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
        .unwrap()
    }

    fn engine(block: &VirtioBlock) -> &NbdFileEngine {
        match &block.disk.file_engine {
            FileEngine::Nbd(engine) => engine,
            _ => panic!("not an NBD block device"),
        }
    }

    fn engine_mut(block: &mut VirtioBlock) -> &mut NbdFileEngine {
        match &mut block.disk.file_engine {
            FileEngine::Nbd(engine) => engine,
            _ => panic!("not an NBD block device"),
        }
    }

    fn wait_for(what: &str, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn serve(block: &mut VirtioBlock, mem: &GuestMemoryMmap, vq: &VirtQueue) {
        let mut queue = vq.create_queue();
        // As the device's own queue, which a restore checks.
        queue.max_size = FIRECRACKER_MAX_QUEUE_SIZE;
        set_queue(block, 0, queue);
        block.activate(mem.clone(), default_interrupt()).unwrap();
        block.threaded_start();
        assert!(engine(block).is_serving());
    }

    fn notify(block: &VirtioBlock) {
        block.queue_evts[0].write(1).unwrap();
    }

    /// Queue the `n`th request, with a header, `segments` data buffers and a status, from
    /// descriptor `4 * n` on. Returns the status address.
    fn add_request(
        vq: &VirtQueue,
        n: u16,
        request_type: u32,
        sector: u64,
        segments: &[(u64, u32)],
    ) -> GuestAddress {
        let header_addr = 0x1000 + 16 * u64::from(n);
        let status_addr = GuestAddress(0x1800 + u64::from(n));
        vq.memory()
            .write_obj(
                RequestHeader::new(request_type, sector),
                GuestAddress(header_addr),
            )
            .unwrap();
        let first = 4 * n;
        vq.dtable[usize::from(first)].set(header_addr, 16, VIRTQ_DESC_F_NEXT, first + 1);
        let data_flags = match request_type {
            VIRTIO_BLK_T_OUT => VIRTQ_DESC_F_NEXT,
            _ => VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        };
        let mut idx = first + 1;
        for &(addr, len) in segments {
            vq.dtable[usize::from(idx)].set(addr, len, data_flags, idx + 1);
            idx += 1;
        }
        vq.dtable[usize::from(idx)].set(status_addr.0, 1, VIRTQ_DESC_F_WRITE, 0);
        vq.memory().write_obj(0xffu8, status_addr).unwrap();
        let avail = vq.avail.idx.get();
        vq.avail.ring[usize::from(avail % 32)].set(first);
        vq.avail.idx.set(avail + 1);
        status_addr
    }

    fn status(mem: &GuestMemoryMmap, addr: GuestAddress) -> u32 {
        u32::from(mem.read_obj::<u8>(addr).unwrap())
    }

    fn pattern(seed: u32, len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(seed) % 251) as u8)
            .collect()
    }

    #[test]
    fn test_config() {
        let server = TestServer::new(DISK_SIZE);
        let mut config = BlockDeviceConfig {
            drive_id: "nbd".to_string(),
            nbd: Some(server.config()),
            ..Default::default()
        };
        // No path, and the engine follows from the NBD settings.
        let virtio = VirtioBlockConfig::try_from(&config).unwrap();
        assert_eq!(virtio.file_engine_type, FileEngineType::Nbd);
        // Not with another engine, nor the NBD engine without them.
        config.file_engine_type = Some(FileEngineType::Threaded);
        VirtioBlockConfig::try_from(&config).unwrap_err();
        config.file_engine_type = Some(FileEngineType::Nbd);
        config.nbd = None;
        config.path_on_host = Some("/dev/null".to_string());
        VirtioBlockConfig::try_from(&config).unwrap_err();

        let block = nbd_block(&server);
        assert_eq!(block.file_engine_type(), FileEngineType::Nbd);
        assert_eq!(block.config_space.capacity, (DISK_SIZE >> 9) as u64);
        assert_ne!(block.avail_features() & (1 << VIRTIO_BLK_F_SEG_MAX), 0);
        assert_ne!(block.avail_features() & (1 << VIRTIO_BLK_F_FLUSH), 0);
        // The device reports its NBD settings, and no path.
        let config: BlockDeviceConfig = block.config().into();
        assert_eq!(config.nbd, Some(server.config()));
        assert_eq!(config.path_on_host, None);
        assert_eq!(config.file_engine_type, Some(FileEngineType::Nbd));
        // There is no file to replace.
        let mut block = block;
        block
            .update_disk_image("/dev/null".to_string())
            .unwrap_err();
    }

    #[test]
    fn test_read_write() {
        let server = TestServer::new(DISK_SIZE);
        let mut block = nbd_block(&server);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 32);
        serve(&mut block, &mem, &vq);

        // Write 4 KiB from three scattered buffers.
        let data = pattern(1, 4096);
        mem.write_slice(&data[..512], GuestAddress(0x4000)).unwrap();
        mem.write_slice(&data[512..3584], GuestAddress(0x6000))
            .unwrap();
        mem.write_slice(&data[3584..], GuestAddress(0x2000))
            .unwrap();
        let st = add_request(
            &vq,
            0,
            VIRTIO_BLK_T_OUT,
            8,
            &[(0x4000, 512), (0x6000, 3072), (0x2000, 512)],
        );
        notify(&block);
        wait_for("the write", || vq.used.idx.get() == 1);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(server.data(8 * 512, 4096), data);
        assert!(
            block
                .interrupt_trigger()
                .has_pending_interrupt(VirtioInterruptType::Queue(0))
        );

        // Read it back as two buffers.
        let st = add_request(
            &vq,
            1,
            VIRTIO_BLK_T_IN,
            8,
            &[(0x8000, 1024), (0xa000, 3072)],
        );
        notify(&block);
        wait_for("the read", || vq.used.idx.get() == 2);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        assert_eq!(vq.used.ring[1].get().len, 4097);
        let mut buf = vec![0u8; 4096];
        mem.read_slice(&mut buf[..1024], GuestAddress(0x8000))
            .unwrap();
        mem.read_slice(&mut buf[1024..], GuestAddress(0xa000))
            .unwrap();
        assert_eq!(buf, data);

        // The device id is the export's name.
        let st = add_request(&vq, 2, VIRTIO_BLK_T_GET_ID, 0, &[(0xc000, 20)]);
        notify(&block);
        wait_for("the id", || vq.used.idx.get() == 3);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        let mut id = [0u8; VIRTIO_BLK_ID_BYTES as usize];
        mem.read_slice(&mut id, GuestAddress(0xc000)).unwrap();
        assert_eq!(&id[..EXPORT.len()], EXPORT.as_bytes());

        // A flush reaches the server.
        let st = add_request(&vq, 3, VIRTIO_BLK_T_FLUSH, 0, &[]);
        notify(&block);
        wait_for("the flush", || vq.used.idx.get() == 4);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        assert_eq!(server.state.flushes.load(Ordering::SeqCst), 1);

        // A server error is an IO error.
        server.state.fail_flush.store(true, Ordering::SeqCst);
        let st = add_request(&vq, 4, VIRTIO_BLK_T_FLUSH, 0, &[]);
        notify(&block);
        wait_for("the failed flush", || vq.used.idx.get() == 5);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_IOERR);
    }

    #[test]
    fn test_pipelined_out_of_order() {
        let server = TestServer::new(DISK_SIZE);
        server.state.reverse.store(true, Ordering::SeqCst);
        let mut block = nbd_block(&server);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 32);
        serve(&mut block, &mem, &vq);

        // Eight 2 KiB writes at once; the server answers them all, in reverse.
        let mut statuses = Vec::new();
        for n in 0..8u16 {
            let addr = 0x2000 + 0x800 * u64::from(n);
            mem.write_slice(&pattern(u32::from(n), 2048), GuestAddress(addr))
                .unwrap();
            statuses.push(add_request(
                &vq,
                n,
                VIRTIO_BLK_T_OUT,
                4 * u64::from(n),
                &[(addr, 2048)],
            ));
        }
        notify(&block);
        wait_for("the writes", || vq.used.idx.get() == 8);
        let order: Vec<u32> = (0..8).map(|i| vq.used.ring[i].get().id).collect();
        assert_ne!(
            order,
            vec![0, 4, 8, 12, 16, 20, 24, 28],
            "completed in order"
        );
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 4, 8, 12, 16, 20, 24, 28]);
        for (n, st) in statuses.into_iter().enumerate() {
            assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
            assert_eq!(server.data(n * 2048, 2048), pattern(n as u32, 2048));
        }
    }

    #[test]
    fn test_quiesce() {
        let server = TestServer::new(DISK_SIZE);
        let mut block = nbd_block(&server);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 32);
        block.rate_limiter = RateLimiter::new(0, 0, 0, 1000, 0, 1000).unwrap();
        serve(&mut block, &mem, &vq);

        // Nothing written: nothing to flush.
        block.quiesce().unwrap();
        assert_eq!(server.state.flushes.load(Ordering::SeqCst), 0);
        assert!(!engine(&block).is_serving());
        block.process_virtio_queues().unwrap();
        assert!(engine(&block).is_serving());

        // A write held back by the server is waited for, then flushed, before the queue comes
        // back, as the worker left it.
        server.state.stall.store(true, Ordering::SeqCst);
        mem.write_slice(&pattern(9, 4096), GuestAddress(0x2000))
            .unwrap();
        let st = add_request(&vq, 0, VIRTIO_BLK_T_OUT, 0, &[(0x2000, 4096)]);
        notify(&block);
        wait_for("the write to arrive", || {
            server.state.requests.load(Ordering::SeqCst) == 1
        });
        let unstall = {
            let state = server.state.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                state.stall.store(false, Ordering::SeqCst);
            })
        };
        block.quiesce().unwrap();
        unstall.join().unwrap();
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(server.state.flushes.load(Ordering::SeqCst), 1);
        assert!(!engine(&block).is_serving());
        assert_eq!(block.queues[0].next_avail.0, 1);
        assert_eq!(block.queues[0].next_used.0, 1);
        // The device has its rate limiter back.
        let config: crate::vmm_config::RateLimiterConfig = (&block.rate_limiter).into();
        assert_eq!(config.ops.unwrap().size, 1000);
        // prepare_save then has nothing left to do.
        block.prepare_save();
        assert_eq!(server.state.flushes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_stop_timeout_keeps_serving() {
        let server = TestServer::new(DISK_SIZE);
        let mut block = nbd_block(&server);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 32);
        serve(&mut block, &mem, &vq);

        server.state.stall.store(true, Ordering::SeqCst);
        let st = add_request(&vq, 0, VIRTIO_BLK_T_OUT, 0, &[(0x2000, 512)]);
        notify(&block);
        wait_for("the write to arrive", || {
            server.state.requests.load(Ordering::SeqCst) == 1
        });
        let mut rate_limiter = RateLimiter::default();
        let err = engine_mut(&mut block)
            .stop_within(&mut rate_limiter, Duration::from_millis(50))
            .unwrap_err();
        assert!(matches!(err, NbdIoError::StopTimeout), "{err:?}");
        // The worker still serves the queue, and completes the write once the server answers.
        assert!(engine(&block).is_serving());
        server.state.stall.store(false, Ordering::SeqCst);
        wait_for("the write", || vq.used.idx.get() == 1);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);

        // A failed flush fails the stop too.
        server.state.fail_flush.store(true, Ordering::SeqCst);
        block.quiesce().unwrap_err();
        assert!(engine(&block).is_serving());
        server.state.fail_flush.store(false, Ordering::SeqCst);
        block.quiesce().unwrap();
    }

    #[test]
    fn test_reconnect() {
        let server = TestServer::new(DISK_SIZE);
        let mut block = nbd_block(&server);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 32);
        serve(&mut block, &mem, &vq);

        // Requests in flight when the connection drops are sent again on a new one.
        server.state.stall.store(true, Ordering::SeqCst);
        let mut statuses = Vec::new();
        for n in 0..4u16 {
            let addr = 0x2000 + 0x1000 * u64::from(n);
            mem.write_slice(&pattern(100 + u32::from(n), 4096), GuestAddress(addr))
                .unwrap();
            statuses.push(add_request(
                &vq,
                n,
                VIRTIO_BLK_T_OUT,
                8 * u64::from(n),
                &[(addr, 4096)],
            ));
        }
        notify(&block);
        wait_for("the writes to arrive", || {
            server.state.requests.load(Ordering::SeqCst) == 4
        });
        server.kill_connection();
        server.state.stall.store(false, Ordering::SeqCst);
        wait_for("the writes", || vq.used.idx.get() == 4);
        assert_eq!(server.state.connections.load(Ordering::SeqCst), 2);
        for (n, st) in statuses.into_iter().enumerate() {
            assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
            assert_eq!(server.data(n * 4096, 4096), pattern(100 + n as u32, 4096));
        }

        // And the new connection serves reads.
        let st = add_request(&vq, 4, VIRTIO_BLK_T_IN, 8, &[(0xc000, 4096)]);
        notify(&block);
        wait_for("the read", || vq.used.idx.get() == 5);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        let mut buf = vec![0u8; 4096];
        mem.read_slice(&mut buf, GuestAddress(0xc000)).unwrap();
        assert_eq!(buf, pattern(101, 4096));
    }

    #[test]
    fn test_persistence() {
        let server = TestServer::new(DISK_SIZE);
        let mut block = nbd_block(&server);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 32);
        serve(&mut block, &mem, &vq);
        mem.write_slice(&pattern(7, 512), GuestAddress(0x2000))
            .unwrap();
        add_request(&vq, 0, VIRTIO_BLK_T_OUT, 0, &[(0x2000, 512)]);
        notify(&block);
        wait_for("the write", || vq.used.idx.get() == 1);

        block.quiesce().unwrap();
        block.prepare_save();
        let mut snapshot = vec![0; 4096];
        crate::snapshot::Snapshot::new(block.save())
            .save(&mut snapshot.as_mut_slice())
            .unwrap();
        // The old process goes away, and with it its connection.
        drop(block);

        let mut restored = VirtioBlock::restore(
            BlockConstructorArgs { mem: mem.clone() },
            &crate::snapshot::Snapshot::load_without_crc_check(snapshot.as_slice())
                .unwrap()
                .data,
        )
        .unwrap();
        assert_eq!(restored.file_engine_type(), FileEngineType::Nbd);
        assert_eq!(restored.disk.nbd, Some(server.config()));
        assert_eq!(server.state.connections.load(Ordering::SeqCst), 2);

        // It serves the queue where the old one left it.
        restored.activate(mem.clone(), default_interrupt()).unwrap();
        restored.threaded_start();
        let st = add_request(&vq, 1, VIRTIO_BLK_T_IN, 0, &[(0x4000, 512)]);
        notify(&restored);
        wait_for("the read", || vq.used.idx.get() == 2);
        assert_eq!(status(&mem, st), VIRTIO_BLK_S_OK);
        let mut buf = vec![0u8; 512];
        mem.read_slice(&mut buf, GuestAddress(0x4000)).unwrap();
        assert_eq!(buf, pattern(7, 512));
    }
}
