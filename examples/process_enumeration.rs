#[allow(unused)]
use core::mem;

use thermite::enumeration::*;
use thermite::info;
use thermite::models::windows::system_info::SystemProcessInformation;


/// Small stucture to represent a process
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
	pub proc_info: *const SystemProcessInformation,
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
	match unsafe { processes::find_process_by_name(process_name, sys_proc_info_ptr) } {
		None => info!("Process {} not found", process_name),
		Some(process) => {
			info!("{} Info :\n{:#?}", process_name, unsafe { read_process_info(process) });
		},
	};

	// Enumerate all processes
	let processes = unsafe { processes::enumerate_processes(sys_proc_info_ptr) };
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
unsafe fn read_process_info(proc_info_ptr: *const SystemProcessInformation) -> Process {
	let mut threads = (*proc_info_ptr).threads.to_vec();
	threads.set_len((*proc_info_ptr).number_of_threads as usize);

	Process {
		pid: (*proc_info_ptr).unique_process_id as _,
		name: (*proc_info_ptr).image_name.to_string(),
		proc_info: proc_info_ptr,
		threads: threads.iter().map(|thr| {
			Thread {
				thread_id: thr.client_id.unique_thread as _,
				start_address: thr.start_address as _,
				priority: thr.priority,
				state: thr.thread_state,
			}
		}).collect()
	}
}


// To read more on this :
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/query.htm
// https://medium.com/@s12deff/list-processes-techniques-cheatsheet-de358f043792