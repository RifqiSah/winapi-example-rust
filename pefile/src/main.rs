use std::*;
use std::ffi::CString;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, SetFilePointerEx, FILE_BEGIN, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING
};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::IMAGE_DOS_SIGNATURE;

use windows::core::PCSTR;

#[repr(C)]
#[derive(Debug, Default)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,   // Magic number ("MZ")
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,  // Offset ke PE Header
}

fn main() {
    let path = CString::new("C:\\Windows\\System32\\notepad.exe").unwrap(); // Ganti dengan file lain jika perlu

    unsafe{
        let h_file: HANDLE = CreateFileA(
        PCSTR(path.as_bytes_with_nul().as_ptr()), GENERIC_READ.0, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), HANDLE(0)).expect("Cannot open file");

        let mut dos_header = IMAGE_DOS_HEADER::default();
        let mut bytes_read: u32 = 0;
        let dos_header_slice = std::slice::from_raw_parts_mut(
            &mut dos_header as *mut _ as *mut u8,
            mem::size_of::<IMAGE_DOS_HEADER>(),
        );

        if ReadFile(h_file, Some(dos_header_slice), Some(&mut bytes_read), None).is_err() {
            eprintln!("Failed to read DOS header!");
            return;
        }

        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            eprintln!("Not a valid PE file!");
            return;
        }

        println!("DOS Header Magic: {:#X}", dos_header.e_magic);
        println!("PE Offset: {:#X}", dos_header.e_lfanew);

        let mut nt_headers = IMAGE_NT_HEADERS64::default();
        let offset = dos_header.e_lfanew as i64;

        SetFilePointerEx(h_file, offset, None, FILE_BEGIN)
            .expect("Failed to set file pointer");

        let nt_headers_slice = std::slice::from_raw_parts_mut(
            &mut nt_headers as *mut _ as *mut u8,
            mem::size_of::<IMAGE_NT_HEADERS64>(),
        );

        if ReadFile(h_file, Some(nt_headers_slice), Some(&mut bytes_read), None).is_err() {
            eprintln!("Gagal membaca NT headers!");
        }

        println!("PE Signature: {:#X}", nt_headers.Signature);
        println!("Machine Type: {:#X}", nt_headers.FileHeader.Machine.0);
        println!("Number of Sections: {}", nt_headers.FileHeader.NumberOfSections);
        println!("Characteristics: {:#X}", nt_headers.FileHeader.Characteristics.0);

        let _ = CloseHandle(h_file);
    }
}
