use core::mem;
use std::process;

use thermite::{debug, error, info};
use thermite::indirect_syscall as syscall;
use thermite::models::windows::*;
use thermite::models::windows::nt_status::NtStatus;
use thermite::models::windows::system_info::{SYSTEM_INFORMATION_CLASS, SYSTEM_PROCESS_INFORMATION};

// use thermite::models::windows::system_info::SYSTEM_INFORMATION_CLASS::SystemProcessInformation;


#[derive(Debug)]
pub struct Process {
	pub pid: u64,
	pub name: String,
	pub proc_info: *const SYSTEM_PROCESS_INFORMATION,
}


fn main() {
	unsafe {
		let sys_proc_info_ptr = get_system_proc_info_ptr();
		let process = find_proc_by_name("Notepad.exe", sys_proc_info_ptr).unwrap();

		debug!((*process.proc_info));
	};
}


/// This function returns a pointer to the system process information table.
///
/// It will call the NtQuerySystemInformation and the NtAllocateVirtualMemory syscalls
///
unsafe fn get_system_proc_info_ptr() -> *const SYSTEM_PROCESS_INFORMATION {
	let mut buffer: *mut std::ffi::c_void = 0u32 as _;
	let mut buf_size: isize = 0;

	// We need to call the NtQuerySystemInformation once to get the size of the buffer needed to store its output
	syscall!("NtQuerySystemInformation",
	    (SYSTEM_INFORMATION_CLASS::SystemProcessInformation),       // [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
	    0,                                                          // [in, out]       PVOID                    SystemInformation,
	    0,                                                          // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size);                                             // [out, optional] PULONG                   ReturnLength

	// let _requested_memory = buf_size;
	// We have now received the size of memory we need to allocate
	debug!("> We need to allocate:", buf_size);

	// We now need to allocate a buffer for the result of the function
	syscall!("NtAllocateVirtualMemory",
        NtCurrentProcess,          // [in]      HANDLE    ProcessHandle,
        &mut buffer,               // [in, out] PVOID     *BaseAddress,
        0u32,                      // [in]      PULONG    ZeroBits,
        &mut buf_size,             // [in, out] PSIZE_T   RegionSize,
        MEM_COMMIT | MEM_RESERVE,  // [in]      ULONG     AllocationType,
        PAGE_EXECUTE_READWRITE);
	// [in]      ULONG     Protect
	info!("Allocated {} bytes of memory at address {:#x?}", buf_size, buffer);

	// We can now make a second call, this time with teh memory already allocated to store the result
	let mut buf_size_2: isize = 0;
	syscall!("NtQuerySystemInformation",
	    (SYSTEM_INFORMATION_CLASS::SystemProcessInformation),   // [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
	    buffer as *mut _,                                       // [in, out]       PVOID                    SystemInformation,
	    buf_size,                                               // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size_2);                                       // [out, optional] PULONG                   ReturnLength

	(buffer as *mut _) as *const SYSTEM_PROCESS_INFORMATION
}


///
/// This function iterates over every SYSTEM_PROCESS_INFORMATION entry until it finds one with the matching name
unsafe fn find_proc_by_name(name: &str, proc_info_ptr: *const SYSTEM_PROCESS_INFORMATION) -> Option<Process> {

	// If the name matches, we return now
	let proc_name = (*proc_info_ptr).image_name.to_string();
	if name.to_string().eq_ignore_ascii_case(&proc_name) {
		return Some(Process {
			name: proc_name,
			pid: (*proc_info_ptr).unique_process_id as u64,
			proc_info: proc_info_ptr,
		});
	}

	// If not, the name doesn't match, we get the offset of the next entry and recurse to it
	let next = (*proc_info_ptr).next_entry_offset;
	if next.ne(&0) { return find_proc_by_name(name, proc_info_ptr.byte_offset(next as isize)); } else { return None; }
}


// To read more on this :
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
// https://medium.com/@s12deff/list-processes-techniques-cheatsheet-de358f043792
