use crate::info;
use crate::models::windows::system_info::SystemProcessInformation;
use crate::models::windows::system_info::SystemInformationClass;
use crate::indirect_syscall as syscall;
use crate::models::windows::{NT_CURRENT_PROCESS, PAGE_EXECUTE_READWRITE, MEM_RESERVE, MEM_COMMIT};


/// This function returns a pointer to the system process information table.
///
/// It will perform system calls to `NtQuerySystemInformation` and `NtAllocateVirtualMemory`
///
/// # Returns  
/// A raw pointer to the [SystemProcessInformation] table.
pub fn get_process_info_ptr() -> *const SystemProcessInformation {
	let mut buffer: *mut std::ffi::c_void = 0u32 as _;
	let mut buf_size: isize = 0;

	let info_class = SystemInformationClass::SystemProcessInformation;
	// We need to call the NtQuerySystemInformation once to get the size of the buffer needed to store its output
	syscall!("NtQuerySystemInformation",
	    info_class,                    // [in]            SystemInformationClass SystemInformationClass // (0x05) for processes
	    0,                             // [in, out]       PVOID                    SystemInformation,
	    0,                             // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size);                // [out, optional] PULONG                   ReturnLength

	// We now need to allocate a buffer for the result of the function
	syscall!("NtAllocateVirtualMemory",
        NT_CURRENT_PROCESS,         // [in]      HANDLE    ProcessHandle,
        &mut buffer,                // [in, out] PVOID     *BaseAddress,
        0u32,                       // [in]      PULONG    ZeroBits,
        &mut buf_size,              // [in, out] PSIZE_T   RegionSize,
        MEM_COMMIT | MEM_RESERVE,   // [in]      ULONG     AllocationType,
        PAGE_EXECUTE_READWRITE);
	// [in]      ULONG     Protect
	info!("Allocated {} bytes of memory at address {:#x?}", buf_size, buffer);

	// We can now make a second call, this time with teh memory already allocated to store the result
	let mut buf_size_2: isize = 0;
	syscall!("NtQuerySystemInformation",
	    info_class, // [in]            SystemInformationClass SystemInformationClass,
	    buffer as *mut _,              // [in, out]       PVOID                    SystemInformation,
	    buf_size,                      // [in]            ULONG                    SystemInformationLength,
	    &mut buf_size_2);              // [out, optional] PULONG                   ReturnLength

	(buffer as *mut _) as *const SystemProcessInformation
}


/// Recursively iterates over the process info table
///
/// Returns an array of tuples, each representing a process and each containing :
/// - the process name, String
/// - the process PID, usize
/// - a pointer to the process information, *const SystemProcessInformation
///
/// ### Safety
///
/// blah blah blah unsafe
/// I write those mostly so that clippy stops screaming tbh
pub unsafe fn enumerate_processes(proc_info_ptr: *const SystemProcessInformation) -> Vec<(String, usize, *const SystemProcessInformation)> {
	let name = (*proc_info_ptr).image_name.to_string();
	let pid = (*proc_info_ptr).unique_process_id as usize;
	let ptr = proc_info_ptr;

	let mut procs: Vec<(String, usize, *const _)> = Vec::new();
	procs.push((name, pid, ptr));

	let next = (*proc_info_ptr).next_entry_offset;
	if next == 0 {
		return procs;
	}
	let mut vec2 = enumerate_processes(proc_info_ptr.byte_offset(next as isize));
	procs.append(&mut vec2);
	return procs;
}


/// This function iterates over every [SystemProcessInformation] entry until it finds one with the matching name
///
/// ### Safety
///
/// This function is unsafe because it must dereference raw pointer to SystemProcessInformation.
pub unsafe fn find_process_by_name(name: &str, proc_info_ptr: *const SystemProcessInformation) -> Option<*const SystemProcessInformation> {
	let proc_name = (*proc_info_ptr).image_name.to_string();
	if name.to_string().eq_ignore_ascii_case(&proc_name) {
		return Some(proc_info_ptr);
	}

	let next = (*proc_info_ptr).next_entry_offset;
	if next.ne(&0) { find_process_by_name(name, proc_info_ptr.byte_offset(next as isize)) } else { None }
}