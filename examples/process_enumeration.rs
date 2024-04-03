use core::mem;
use std::process;

use thermite::{debug, error, info};
use thermite::indirect_syscall as syscall;
use thermite::models::windows::*;
use thermite::models::windows::nt_status::NtStatus;
use thermite::models::windows::system_info::{SYSTEM_INFORMATION_CLASS, SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION};

#[derive(Debug)]
pub struct Process {
	pub pid: u64,
	pub name: String,
	pub proc_info: *const SYSTEM_PROCESS_INFORMATION,
	pub threads: Vec<Thread>,
}
#[derive(Debug)]
pub struct Thread {
	pub thread_id: usize,
	pub start_address: *const u8,
	pub priority: i32,
	pub state:  u32,
}

fn main() {
	unsafe {
		let sys_proc_info_ptr = get_system_proc_info_ptr();
		let process = find_proc_by_name("CalculatorApp.exe", sys_proc_info_ptr).unwrap();
		// debug!(process);

		let processes = enumerate_processes(sys_proc_info_ptr);
		debug!(processes);
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


/// Recursively iterates over the process info table and print the name and PID of every process found.
unsafe fn enumerate_processes(proc_info_ptr: *const SYSTEM_PROCESS_INFORMATION) -> Vec<(String, usize, *const SYSTEM_PROCESS_INFORMATION)> {
	let name = (*proc_info_ptr).ImageName.to_string();
	let pid = (*proc_info_ptr).UniqueProcessId as usize;
    let ptr = proc_info_ptr;

	let mut procs: Vec<(String, usize, *const _)> = Vec::new();
	procs.push((name, pid, ptr));
	// println!("\t - {pid:?} - {name}");

	let next = (*proc_info_ptr).NextEntryOffset;
	if next == 0 {
		return procs;
	}
	let mut vec2 = enumerate_processes(proc_info_ptr.byte_offset(next as isize));
	procs.append(&mut vec2);
	return procs;
}

///
/// This function iterates over every SYSTEM_PROCESS_INFORMATION entry until it finds one with the matching name
unsafe fn find_proc_by_name(name: &str, proc_info_ptr: *const SYSTEM_PROCESS_INFORMATION) -> Option<Process> {
	// If the name matches, we return the Process
	let proc_name = (*proc_info_ptr).ImageName.to_string();
	if name.to_string().eq_ignore_ascii_case(&proc_name) {
		return Some(read_process_info(proc_info_ptr));
	}

	// If the name doesn't match, we get the offset of the next entry and recurse to it
	let next = (*proc_info_ptr).NextEntryOffset;
	if next.ne(&0) { return find_proc_by_name(name, proc_info_ptr.byte_offset(next as isize)); } else { return None; }
}

unsafe fn read_process_info(proc_info_ptr: *const SYSTEM_PROCESS_INFORMATION) -> Process {
	let mut threads = (*proc_info_ptr).Threads.to_vec();
	threads.set_len((*proc_info_ptr).NumberOfThreads as usize);
	// let u: Vec<&SYSTEM_THREAD_INFORMATION> = ;

	Process {
		pid: (*proc_info_ptr).UniqueProcessId as _,
		name: (*proc_info_ptr).ImageName.to_string(),
		proc_info: proc_info_ptr,
		threads: threads.iter().map(|thr| {
			Thread {
				thread_id: thr.ClientId.UniqueThread as _,
				start_address: thr.StartAddress as _,
				priority: thr.Priority,
				state: thr.ThreadState,
			}
		}).collect()
	}
}

// To read more on this :
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
// https://medium.com/@s12deff/list-processes-techniques-cheatsheet-de358f043792
