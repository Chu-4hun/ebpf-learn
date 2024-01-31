#![no_std]
#![no_main]
// ERR can't find crate for `test` fixed in .vscode/settings.json
// https://stackoverflow.com/questions/65722396/how-to-avoid-e0463-cant-find-crate-for-test-cant-find-crate-when-building
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

use aya_bpf::{
    cty::c_ulong,
    macros::{lsm, map},
    maps::{HashMap, PerfEventByteArray, RingBuf},
    programs::{LsmContext, XdpContext},
};
use aya_log_ebpf::{error, info};
use core::mem;
use vmlinux::file;

/* flags u32 for BPF_MAP_UPDATE_ELEM command */
// BPF_ANY       0 /* create new element or update existing */
// BPF_NOEXIST   1 /* create new element only if it didn't exist */
// BPF_EXIST     2 /* only update existing element */
// #[map]
// static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

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

#[map]
static PATHS: RingBuf = RingBuf::with_byte_size(8*32*10,0);

#[lsm(hook = "file_open")]
pub fn file_hook(ctx: LsmContext) -> i32 {
    match unsafe { try_file_hook(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_file_hook(ctx: LsmContext) -> Result<i32, i32> {
    let file: *const file = ctx.arg(0);
    let _clone_flags: c_ulong = ctx.arg(1);
    // let retval: c_int = ctx.arg(2);
    // (*((*file).f_path.dentry)).d_name
    // (*file).
    let value= (*((*file).f_path.dentry)).d_iname;

    // let mut entry = PATHS.reserve::<Vec<u8>>(0);

    // PATHS.output(&value, 0);


    match PATHS.output(&value, 0){
        // Ok(_) => info!(&ctx, "done"),
        Ok(_) => (),
        Err(_) => (),
    }
    

    // if let Some(mut entry) = entry {
        // entry.insert(value);
        // entry.submit(0);
    // } else {
    // }

    // PATHS.push(&g, 0).map_err(|e| e as i32)?;

    // Handle results of previous LSM programs.
    // if retval != 0 {
    //     return Ok(retval);
    // }

    Ok(0)
}
