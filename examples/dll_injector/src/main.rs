use std::{
    env,
    ffi::{c_void, CString},
};
use sysinfo::{ProcessExt, System, SystemExt};
use windows::Win32::{
    Foundation::{CloseHandle, BOOL, HANDLE, PSTR},
    Security::SECURITY_ATTRIBUTES,
    System::{
        Diagnostics::Debug::WriteProcessMemory,
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        Threading::{CreateRemoteThread, OpenProcess, PROCESS_ACCESS_RIGHTS},
    },
};

fn main() {
    // Get the process name argument
    let process_name = env::args().nth(1).expect(
        "expected process name with full file extension (ex. 'notepad.exe') as first parameter",
    );

    // Get the dll path argument
    let dll_path = env::args()
        .nth(2)
        .expect("expected full file path to dll as second parameter");

    // Get the size of the path for the dll. This is +1 for null-termination of the string
    let dll_path_size = dll_path.len() + 1;

    // Get the target process id using the process name
    let target_process_id = *get_process_id(&process_name)
        .get(0)
        .expect("failed getting process");

    // Retrieve a handle to the process
    let process_handle = open_process(target_process_id).unwrap();

    // Allocate memory for the dll path's string
    let allocated_memory_region = allocate_memory_region(process_handle, dll_path_size);

    // Create a CString of the dll path to be passed to the Windows C API function WriteProcessMemory
    let dll_path_cstring = CString::new(dll_path).unwrap();

    // Call WriteProcessMemory
    write_process_memory(
        process_handle,
        allocated_memory_region,
        dll_path_cstring,
        dll_path_size,
    );

    // Get the LoadLibraryA kernel32.dll function.
    // Refer to https://stackoverflow.com/questions/22750112/dll-injection-with-createremotethread for information
    // on why it is possible in the first place to take LoadLibraryA in the current process, and use it in another process
    let load_library = get_module_library("kernel32.dll", "LoadLibraryA");

    // Create the remote thread
    create_remote_thread(process_handle, load_library, allocated_memory_region);

    // Close the handle to the process
    close_handle(process_handle);
}

// Find the id of a process using its name
pub fn get_process_id(process_name: &str) -> Vec<usize> {
    let sys = System::new_all();
    let mut process_vec = Vec::new();

    for (pid, process) in sys.processes() {
        if process.name() == process_name {
            process_vec.push(pid.clone());
        }
    }

    process_vec
}

// Open a process and get the handle to it
pub fn open_process(process_id: usize) -> Result<HANDLE, String> {
    let process_rights = PROCESS_ACCESS_RIGHTS(0x1F0FFF);

    let process_handle =
        unsafe { OpenProcess(process_rights, BOOL::from(false), process_id as u32) };

    if process_handle.0 == 0 {
        Err(format!("failed opening process with id: {}", process_id))
    } else {
        Ok(process_handle)
    }
}

fn allocate_memory_region(process_handle: HANDLE, dll_path_size: usize) -> *mut c_void {
    unsafe {
        VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    }
}

fn write_process_memory(
    process_handle: HANDLE,
    allocated_memory_region: *mut c_void,
    dll_path_cstring: CString,
    dll_path_size: usize,
) {
    unsafe {
        WriteProcessMemory(
            process_handle,
            allocated_memory_region,
            dll_path_cstring.as_ptr() as *const c_void,
            dll_path_size,
            std::ptr::null_mut(),
        )
    };
}

fn get_module_library(module: &str, function: &str) -> unsafe extern "system" fn() -> isize {
    let module_cstring = CString::new(module).unwrap();
    let module_raw = module_cstring.into_raw() as *mut u8;

    let function_cstring = CString::new(function).unwrap();
    let function_raw = function_cstring.into_raw() as *mut u8;

    unsafe { GetProcAddress(GetModuleHandleA(PSTR(module_raw)), PSTR(function_raw)) }.unwrap()
}

fn create_remote_thread(
    process_handle: HANDLE,
    start_address: unsafe extern "system" fn() -> isize,
    allocated_memory_region: *mut c_void,
) {
    unsafe {
        CreateRemoteThread(
            process_handle,
            0 as *mut SECURITY_ATTRIBUTES,
            0,
            Some(std::mem::transmute(start_address)),
            allocated_memory_region,
            0,
            0 as *mut u32,
        )
    };
}

fn close_handle(process_handle: HANDLE) {
    unsafe { CloseHandle(process_handle) };
}
