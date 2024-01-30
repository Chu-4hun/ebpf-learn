#![no_std]
#![no_main]
// ERR can't find crate for `test` fixed in .vscode/settings.json
// https://stackoverflow.com/questions/65722396/how-to-avoid-e0463-cant-find-crate-for-test-cant-find-crate-when-building
#[allow(non_camel_case_types, non_upper_case_globals)]
pub mod vmlinux;

use core::mem;
use aya_log_ebpf::info;
use vmlinux::file;
use aya_bpf::{bindings::{xdp_action}, cty::c_int, macros::{lsm, map, xdp}, maps::HashMap, programs::{LsmContext, XdpContext}};

/* flags u32 for BPF_MAP_UPDATE_ELEM command */
// BPF_ANY       0 /* create new element or update existing */
// BPF_NOEXIST   1 /* create new element only if it didn't exist */
// BPF_EXIST     2 /* only update existing element */
#[map] 
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// #[map]
// static PROCESSES: HashMap<i32, i32> = HashMap::with_max_entries(32768, 0);

#[lsm(hook = "file_open")]
pub fn file_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_file_hook(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_file_hook(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const file = ctx.arg(0);
    // let _clone_flags: c_ulong = ctx.arg(1);
    // let retval: c_int = ctx.arg(2);
    let g = (*((*file).f_path.dentry)).d_iname;

    // let path = 
    //     core::str::from_utf8(g.as_ref());
    
    // if let Ok(path) = path{
    //     info!(&ctx,"file {} opened", path);
    //     return Ok(0);
    // }
    
    info!(&ctx, "gg");
    // PROCESSES.insert(&pid, &pid, 0).map_err(|e| e as i32)?;

    // // Handle results of previous LSM programs.
    // if retval != 0 {
    //     return Ok(retval);
    // }

    Ok(0)
}


