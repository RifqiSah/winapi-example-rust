use std::ffi::CString;

use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK, MB_ICONINFORMATION};
use windows::core::PCSTR;

fn main() {
    let title = CString::new("Rust MessageBox").unwrap();
    let message = CString::new("Hello from Rust!").unwrap();

    unsafe {
        MessageBoxA(None, PCSTR(message.as_ptr().cast()), PCSTR(title.as_ptr().cast()), MB_OK | MB_ICONINFORMATION);
    }
}
