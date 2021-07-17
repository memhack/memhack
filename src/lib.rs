use bindings::Windows::Win32::{
    Debug::WriteProcessMemory,
    SystemServices::PROCESS_ACCESS_RIGHTS,
    WindowsAndMessaging::{MessageBoxA, HWND, MESSAGEBOX_STYLE},
};
use bindings::Windows::{
    self,
    Win32::{Debug::ReadProcessMemory, SystemServices::OpenProcess},
};

use bindings::Windows::Win32::Debug::GetLastError;
use sysinfo::{Process, ProcessExt, System, SystemExt};
use Windows::Win32::SystemServices::HANDLE;

use std::{ffi::c_void, vec};

pub fn get_processes(process_name: &str) -> Vec<usize> {
    let sys = System::new_all();
    let mut process_vec = Vec::new();

    for (pid, process) in sys.processes().iter() {
        if process.name() == process_name {
            process_vec.push(pid.clone());
        }
    }

    process_vec
}

pub fn open_process(process_id: usize) -> Result<Windows::Win32::SystemServices::HANDLE, String> {
    let process_rights = PROCESS_ACCESS_RIGHTS::from(0x1F0FFF);

    let process_handle = unsafe {
        OpenProcess(
            process_rights,
            Windows::Win32::SystemServices::BOOL::from(false),
            process_id as u32,
        )
    };

    if process_handle.is_null() {
        Err(format!("failed opening process with id: {}", process_id))
    } else {
        Ok(process_handle)
    }
}

pub fn read_process_memory(process: HANDLE, addr: usize, amount: usize) -> Result<Vec<u8>, String> {
    let mut vec: Vec<u8> = vec![0; amount];

    let mut bytes_read: usize = 0;
    let bytes_read_ptr: *mut usize = &mut bytes_read;

    let result = unsafe {
        ReadProcessMemory(
            process,
            addr as *mut c_void,
            vec.as_mut_ptr() as *mut c_void,
            amount,
            bytes_read_ptr,
        )
    };

    if result.0 == 0 {
        // To get extended information, call GetLastError()
        let get_last_error = unsafe { GetLastError() };

        return Err(format!(
            "ReadProcessMemory failed, ensure the address is correct. GetLastError code: {}",
            get_last_error
        ));
    }

    if amount != bytes_read {
        return Err(format!(
            "expected to read {} bytes, read only {} bytes",
            amount, bytes_read
        ));
    }

    Ok(vec)
}

pub fn write_process_memory(process: HANDLE, addr: usize, buffer: Vec<u8>) -> Result<(), String> {
    let mut bytes_written: usize = 0;
    let bytes_written_ptr: *mut usize = &mut bytes_written;

    let result = unsafe {
        WriteProcessMemory(
            process,
            addr as *mut c_void,
            buffer.as_ptr() as *const c_void,
            buffer.len(),
            bytes_written_ptr,
        )
    };

    if result.0 == 0 {
        // To get extended information, call GetLastError()
        let get_last_error = unsafe { GetLastError() };

        return Err(format!(
            "WriteProcessMemory failed, ensure the address is correct. GetLastError code: {}",
            get_last_error
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
