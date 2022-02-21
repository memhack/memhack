use std::ffi::c_void;
use windows::Win32::Foundation::{BOOL, HINSTANCE};

#[no_mangle]
#[allow(unused_variables)]
#[allow(non_snake_case)]
pub extern "stdcall" fn DllMain(module: HINSTANCE, reason: u32, reserved: *mut c_void) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => start(module),
        DLL_THREAD_ATTACH => (),
        DLL_THREAD_DETACH => (),
        DLL_PROCESS_DETACH => (),
        _ => (),
    }

    BOOL::from(true)
}

fn start(module: HINSTANCE) {
    memhack::open_debug_console().unwrap();

    println!("Hello world!");
}
