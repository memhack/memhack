use std::ffi::c_void;
use windows::Win32::{
    Foundation::{BOOL, HINSTANCE},
    System::SystemServices::{
        DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
    },
};

// Entry point for the Windows DLL, to be injected using a dll injector
#[no_mangle]
#[allow(unused_variables)]
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

// The start function for the dll. In this example it is simply printing out "Hello world!"
fn start(_module: HINSTANCE) {
    if let Err(err) = memhack::open_debug_console() {
        println!("Error opening console: {}", err);
    };

    println!("Hello world!");
}