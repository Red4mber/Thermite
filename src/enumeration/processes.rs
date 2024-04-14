use std::ptr::null_mut;

use ntapi::ntexapi::{PSYSTEM_PROCESS_INFORMATION, SystemProcessInformation};
use ntapi::ntpsapi::NtCurrentProcess;
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PVOID};

use crate::indirect_syscall as syscall;
use crate::info;
use crate::utils::handle_unicode_string;


/// This function returns a pointer to the system process information table.
///
/// It will perform system calls to `NtQuerySystemInformation` and `NtAllocateVirtualMemory`
///
/// # Returns  
/// A raw pointer to the [SystemProcessInformation] table.
pub fn get_process_info() -> PSYSTEM_PROCESS_INFORMATION {
	let mut buffer: PVOID = null_mut();
	let mut buf_size: isize = 0;

	// We need to call the NtQuerySystemInformation once to get the size of the buffer needed to store its output
	syscall!("NtQuerySystemInformation",
	    SystemProcessInformation,      // [in]            SystemInformationClass SystemInformationClass // (0x05) for processes
	    0,                             // [in, out]       PVOID                    SystemInformation,
	    0,                             // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size);                // [out, optional] PULONG                   ReturnLength

	// We now need to allocate a buffer for the result of the function
	syscall!("NtAllocateVirtualMemory",
        NtCurrentProcess,           // [in]      HANDLE    ProcessHandle,
        &mut buffer,                // [in, out] PVOID     *BaseAddress,
        0u32,                       // [in]      PULONG    ZeroBits,
        &mut buf_size,              // [in, out] PSIZE_T   RegionSize,
        MEM_COMMIT | MEM_RESERVE,   // [in]      ULONG     AllocationType,
        PAGE_EXECUTE_READWRITE);    // [in]      ULONG     Protect
	info!("Allocated {} bytes of memory at address {:#x?}", buf_size, buffer);

	// We can now make a second call, this time with teh memory already allocated to store the result
	let mut buf_size_2: isize = 0;
	syscall!("NtQuerySystemInformation",
	    SystemProcessInformation,                    // [in]            SystemInformationClass SystemInformationClass,
	    buffer as *mut _,              // [in, out]       PVOID                    SystemInformation,
	    buf_size,                      // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size_2);              // [out, optional] PULONG                   ReturnLength

	(buffer as *mut _) as PSYSTEM_PROCESS_INFORMATION
}


/// Recursively iterates over the process info table
///
/// Returns an array of tuples, each representing a process and each containing :
/// - the process name, String
/// - the process PID, usize
/// - a pointer to the process information, *const SystemProcessInformation
pub fn enumerate_processes(proc_info_ptr: PSYSTEM_PROCESS_INFORMATION) -> Vec<(String, usize, PSYSTEM_PROCESS_INFORMATION)> {
	let proc_info = unsafe { *proc_info_ptr };
	let name = handle_unicode_string(proc_info.ImageName); // (*proc_info_ptr).ImageName.to_string();
	let pid = proc_info.UniqueProcessId as usize;
	let ptr = proc_info_ptr;

	let mut procs: Vec<(String, usize, PSYSTEM_PROCESS_INFORMATION)> = Vec::new();
	procs.push((name, pid, ptr));

	let next = proc_info.NextEntryOffset;
	if next == 0 {
		return procs;
	}
	let mut vec2 = enumerate_processes(unsafe { proc_info_ptr.byte_offset(next as isize) });
	procs.append(&mut vec2);
	procs
}


/// This function iterates over every [SystemProcessInformation] entry until it finds one with the matching name
pub fn find_process_by_name(name: &str, proc_info_ptr: PSYSTEM_PROCESS_INFORMATION) -> Option<PSYSTEM_PROCESS_INFORMATION> {
	let proc_info = unsafe { *proc_info_ptr };
	let proc_name = handle_unicode_string(proc_info.ImageName);
	if name.to_string().eq_ignore_ascii_case(&proc_name) {
		return Some(proc_info_ptr);
	}

	let next = proc_info.NextEntryOffset;
	if next.ne(&0) { unsafe { find_process_by_name(name, proc_info_ptr.byte_offset(next as isize)) } } else { None }
}

/// This function iterates over every [SystemProcessInformation] entry until it finds one with the matching PID
pub fn find_process_by_pid(pid: u64, proc_info_ptr: PSYSTEM_PROCESS_INFORMATION) -> Option<PSYSTEM_PROCESS_INFORMATION> {
	let proc_info = unsafe { *proc_info_ptr };
	if pid == proc_info.UniqueProcessId as u64 {
		return Some(proc_info_ptr);
	}

	let next = proc_info.NextEntryOffset;
	if next.ne(&0) { unsafe { crate::enumeration::processes::find_process_by_pid(pid, proc_info_ptr.byte_offset(next as isize)) } } else { None }
}