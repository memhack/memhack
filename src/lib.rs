use std::{ffi::c_void, vec};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::{BOOL, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};

pub fn get_processes(process_name: &str) -> Vec<u32> {
    let sys = System::new_all();
    let mut process_vec = Vec::new();

    for (pid, process) in sys.processes().iter() {
        if process.name() == process_name {
            process_vec.push(pid.clone().as_u32());
        }
    }

    process_vec
}

pub fn open_process(process_id: u32) -> Result<HANDLE, String> {
    let process_rights = PROCESS_ACCESS_RIGHTS(0x1F0FFF);

    let process_handle = unsafe { OpenProcess(process_rights, BOOL::from(false), process_id) };

    if process_handle.0 == 0 {
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
            get_last_error.0
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
            get_last_error.0
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
