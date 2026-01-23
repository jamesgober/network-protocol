#[cfg(test)]
mod tests {
    use network_protocol::protocol::dispatcher::Dispatcher;
    use network_protocol::protocol::message::Message;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn benchmark_dispatcher_rwlock_contention() {
        let dispatcher = Arc::new(Dispatcher::new());

        // Register some handlers
        dispatcher.register("PING", |_| Ok(Message::Pong)).unwrap();
        dispatcher.register("PONG", |_| Ok(Message::Ping)).unwrap();
        dispatcher.register("ECHO", |msg| Ok(msg.clone())).unwrap();

        // Number of operations to perform
        let ops = 100_000;
        let reader_threads = 8;
        let writer_threads = 2;

        let start = Instant::now();

        // Spawn reader threads that dispatch messages
        let mut reader_handles = Vec::new();
        for _ in 0..reader_threads {
            let dispatcher = Arc::clone(&dispatcher);
            let handle = thread::spawn(move || {
                let read_ops = ops / reader_threads;
                let mut dispatch_time = Duration::ZERO;

                for i in 0..read_ops {
                    let msg = if i % 2 == 0 {
                        Message::Ping
                    } else {
                        Message::Pong
                    };

                    let dispatch_start = Instant::now();
                    let _ = dispatcher.dispatch(&msg);
                    dispatch_time += dispatch_start.elapsed();
                }

                dispatch_time
            });
            reader_handles.push(handle);
        }

        // Counter for generating unique handler names
        let counter = Arc::new(AtomicUsize::new(0));

        // Spawn writer threads that register new handlers
        let mut writer_handles = Vec::new();
        for w in 0..writer_threads {
            let dispatcher = Arc::clone(&dispatcher);
            let counter = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                let write_ops = ops / (writer_threads * 10); // Fewer writes than reads
                let mut register_time = Duration::ZERO;

                for i in 0..write_ops {
                    let unique_id = counter.fetch_add(1, Ordering::SeqCst);
                    let cmd = format!("CUSTOM_{w}_{i}_{unique_id}");

                    let register_start = Instant::now();
                    let _ = dispatcher.register(&cmd, |_msg| Ok(Message::Pong));
                    register_time += register_start.elapsed();

                    // Small sleep to simulate real-world conditions
                    thread::sleep(Duration::from_micros(5));
                }

                register_time
            });
            writer_handles.push(handle);
        }

        // Collect read times
        let mut total_read_time = Duration::ZERO;
        for handle in reader_handles {
            total_read_time += handle.join().unwrap();
        }

        // Collect write times
        let mut total_write_time = Duration::ZERO;
        for handle in writer_handles {
            total_write_time += handle.join().unwrap();
        }

        let total_time = start.elapsed();
        let avg_read_time = total_read_time / (ops as u32);
        let avg_write_time = total_write_time / ((ops / 10) as u32);

        println!("\n===== Dispatcher RwLock Benchmark =====");
        println!("Total operations: {ops}");
        println!("Reader threads: {reader_threads}");
        println!("Writer threads: {writer_threads}");
        println!("Total time: {total_time:?}");
        println!("Average read (dispatch) time: {avg_read_time:?}");
        println!("Average write (register) time: {avg_write_time:?}");
        println!("=====================================\n");
    }
}
