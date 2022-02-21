use std::{
    error::Error,
    ffi::{c_void, CString},
    vec,
};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use windows::Win32::{
    Foundation::{GetLastError, BOOL, HANDLE, HINSTANCE, PSTR},
    System::{
        Console::{AllocConsole, FreeConsole},
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        LibraryLoader::{FreeLibraryAndExitThread, GetModuleHandleA},
        ProcessStatus::{K32GetModuleInformation, MODULEINFO},
        Threading::{GetCurrentProcess, OpenProcess, PROCESS_ACCESS_RIGHTS},
    },
};

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

pub fn start(module: HINSTANCE) {
    // Debug console
    open_debug_console().unwrap();

    println!("Hello from DLL!");

    // Example of getting base address
    /*let process_base_address = unsafe { GetModuleHandleA(PSTR(std::ptr::null_mut())) };
    println!("Test: {:#01x}", process_base_address.0);
    let p = process_base_address.0 as *const u32;
    let n = unsafe { *p };
    println!("{}", n);*/

    // Example of pattern scanning
    /*let my_cool_pattern = pattern_scan("notepad.exe", "? 15 7B 34 02 ? 48").unwrap();
    println!("{:#01x}", my_cool_pattern);*/

    // TODO: Detouring
}

// Sample pattern scanning reference:
// https://www.unknowncheats.me/forum/league-of-legends/424623-internal-pattern-scanning.html

fn pattern_scan(str: &str, pattern_and_mask: &str) -> Result<usize, Box<dyn Error>> {
    let module = get_module_info(str).expect("failed getting module");

    let base = module.lpBaseOfDll as *mut u8;
    let size = module.SizeOfImage as usize;

    let mut mask = Vec::new();
    let mut pattern = Vec::new();

    let pattern_and_mask_string = String::from(pattern_and_mask);

    for str in pattern_and_mask_string.split(" ") {
        if str.chars().count() > 2 {
            Err(format!("Element {}'s length is greater than 2", str))?
        }

        if str == "??" {
            Err("Only a single question mark should be used")?
        }

        mask.push(str);

        if str == "?" {
            pattern.push(0);
        } else {
            pattern.push(u8::from_str_radix(str, 16).unwrap());
        }
    }

    for i in 0..size - pattern.len() {
        let mut found = true;

        for j in 0..pattern.len() {
            let mask_char = *mask.get(j).unwrap();
            let pattern_byte = *pattern.get(j).unwrap();

            if mask_char != "?" && pattern_byte != unsafe { *base.add(i + j) } {
                found = false;
                break;
            };
        }

        if found {
            return Ok(unsafe { base.add(i) } as usize);
        }
    }

    Err("failed finding signature")?
}

fn get_module_info(module: &str) -> Option<MODULEINFO> {
    let mut awer: MODULEINFO = MODULEINFO {
        lpBaseOfDll: std::ptr::null_mut(),
        SizeOfImage: 0,
        EntryPoint: std::ptr::null_mut(),
    };

    let test = CString::new(module).unwrap();

    let raw = test.into_raw() as *mut u8;

    let h_module = unsafe { GetModuleHandleA(PSTR(raw)) };

    if (h_module.0) == 0 {
        None
    } else {
        unsafe {
            K32GetModuleInformation(
                GetCurrentProcess(),
                h_module,
                &mut awer as *mut MODULEINFO,
                std::mem::size_of::<MODULEINFO>() as u32,
            );
        }
        Some(awer)
    }
}

fn pattern_scan_multithread() {
    //pattern_scan_actual(num_cpus::get())
}

fn pattern_scan_singlethread() {
    //pattern_scan_actual(1)
}

fn open_debug_console() -> Result<(), Box<dyn Error>> {
    if unsafe { AllocConsole() }.0 == 0 {
        Err(format!(
            "failed opening console, GetLastError: {}",
            unsafe { GetLastError() }.0
        ))?
    } else {
        Ok(())
    }
}

fn close_debug_console() -> Result<(), Box<dyn Error>> {
    if unsafe { FreeConsole() }.0 == 0 {
        Err(format!(
            "failed closing console, GetLastError: {}",
            unsafe { GetLastError() }.0
        ))?
    } else {
        Ok(())
    }
}

fn close_cheat(module: HINSTANCE) {
    unsafe {
        FreeLibraryAndExitThread(module, 0);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
