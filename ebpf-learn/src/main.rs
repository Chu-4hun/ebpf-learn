
use aya::maps::RingBuf;
use aya::programs::Lsm;
use aya::{include_bytes_aligned, Bpf, Btf};
use aya_log::BpfLogger;
use clap::Parser;
use tracing::{debug, error, info, warn};
use std::convert::TryFrom;
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(tracing::Level::TRACE)
        // builds the subscriber.
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");


    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf-learn"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-learn"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let btf = Btf::from_sys_fs()?;

    let program: &mut Lsm = bpf.program_mut("file_hook").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    let ring_buf = RingBuf::try_from(bpf.map_mut("PATHS").unwrap()).unwrap();
    let mut poll = AsyncFd::new(ring_buf)?;
    let mut is_looping = true;

    while is_looping {
        let mut guard: tokio::io::unix::AsyncFdReadyMutGuard<'_, RingBuf<&mut aya::maps::MapData>> =
            poll.readable_mut().await.unwrap();

        while let Some(item) = guard.get_inner_mut().next() {
            // item.into_iter().map(|x| );
            let s = match std::str::from_utf8(&item) {
                Ok(v) => debug!("Received: {:?}", v.trim_matches(char::from(0))),
                Err(e) => error!("Invalid UTF-8 sequence: {}", e),
            };

            
        }
        guard.clear_ready();
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    is_looping = false;

    info!("Exiting...");

    Ok(())
}
