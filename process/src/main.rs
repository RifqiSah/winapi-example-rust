use std::ffi::CString;
use windows::Win32::System::Threading::{CreateProcessA, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOA};

use windows::core::PSTR;

fn main() {
    let program = CString::new("C:\\Windows\\System32\\calc.exe").unwrap(); // Path program yang akan dijalankan

    let mut si = STARTUPINFOA::default();
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        // creating process
        let ret = CreateProcessA(None, PSTR(program.as_ptr() as *mut u8), None, None, false, PROCESS_CREATION_FLAGS(0), None, None, &mut si, &mut pi);
        if ret.is_ok() {
            println!("Process started with PID: {}", pi.dwProcessId);
        } else {
            eprintln!("Failed to start process!");
        }
    }
}
