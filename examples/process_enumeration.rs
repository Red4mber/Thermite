#[allow(unused)]
use core::mem;

use ntapi::ntexapi::SYSTEM_PROCESS_INFORMATION;

use thermite::enumeration::*;
use thermite::info;
use thermite::utils::handle_unicode_string;


/// Small structure to represent a process
/// Each [Syscall] struct contains the following fields:
///
/// * `PID` - The process ID (`usize`).
/// * `name` - The name of the process (`String`).
/// * `proc_info` - A raw pointer to the process information (`*const SystemProcessInformation`).
/// * `threads` - A vector containing thread information (`Vec<`[Thread]`>`).
#[derive(Debug)]
pub struct Process {
	pub pid: usize,
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
	// Retrieve system process info
	let sys_proc_info_ptr = processes::get_process_info();
	
	// Searching for a specific process
	let process_name = "Notepad.exe";
	match processes::find_process_by_name(process_name, sys_proc_info_ptr) {
		None => info!("Process {} not found", process_name),
		Some(process) => {
			info!("{} Info :\n{:#?}", process_name, unsafe { read_process_info(process) });
		},
	};

	// Enumerate all processes
	let processes = processes::enumerate_processes(sys_proc_info_ptr);
	for process in processes {
		println!("\t<{}> {}", process.1, process.0)
	}

	// Other utility enumeration functions
	unsafe {
		info!("Command line: {}", get_command_line());
		info!("Current directory: {}", get_current_directory());
	}
	// List all environment variables
	let var = "username";
	match get_environment_var(var) {
		Some(env) => println!("[^-^] {var} = {env}"),
		None => eprintln!("[x_X] Environment variable {var} not found"),
	};
	// Various functions to read environment variables 
	info!(get_computer_name());
	info!(get_username());
	info!(get_temp());
	info!(get_appdata());
	info!(get_windir());
}


// This function reads a process information  and returns a `Process` structure
//
unsafe fn read_process_info(proc_info_ptr: *const SYSTEM_PROCESS_INFORMATION) -> Process {
	let mut threads = (*proc_info_ptr).Threads.to_vec();
	threads.set_len((*proc_info_ptr).NumberOfThreads as usize);

	Process {
		pid: (*proc_info_ptr).UniqueProcessId as _,
		name: handle_unicode_string((*proc_info_ptr).ImageName),
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