use crate::peb_walk::get_teb_address;
use crate::utils::handle_unicode_string;


pub mod processes;


/// Reads the current process's command line from the Process Environment Block.
///  
/// # Returns  
/// Returns a vector containing every environment variables as `String` (with the format "KEY=value")
pub unsafe fn get_environment() -> Vec<String> {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	let length = (*(*peb_ptr).ProcessParameters).EnvironmentSize as usize / 2;
	let env_ptr = (*(*peb_ptr).ProcessParameters).Environment;

	let buffer = std::slice::from_raw_parts(
		env_ptr as *const _, length);

	let env = String::from_utf16_lossy(buffer);
	return env.split('\0').map(|str| {
		str.to_string()
	}).collect()
}


/// Search for a specific environment variable.
///
/// Returns an Option containing its value if the variable exists, otherwise returns None
pub fn get_environment_var(var: &str) -> Option<String> {
	let env = unsafe { get_environment() };
	env.iter().map(|v| v.split('=').collect::<Vec<&str>>()).filter_map(|x| {
		x[0].eq_ignore_ascii_case(var).then(|| x[1..].concat())
	}).next()
}


/// Returns the current process's command line from the Process Environment Block.
///  
/// # Returns  
/// The command line as a `String`
pub unsafe fn get_command_line() -> String {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	handle_unicode_string((*(*peb_ptr).ProcessParameters).CommandLine)
}


/// Returns the OS Version.
///
/// # Safety  
/// This function is unsafe because it relies on the correct structure of the Process Environment Block.  
///  
/// # Returns  
/// Returns the OS Version as a tuple containing the Major version, Minor version and Build number
/// 
pub unsafe fn get_os_version() -> (u32, u32, u32) {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	((*peb_ptr).OSMajorVersion, (*peb_ptr).OSMinorVersion, (*peb_ptr).OSBuildNumber as u32)
}



/// Returns the current working directory of the process from the Process Environment Block.
///  
/// # Returns  
/// The current working directory as a `String`
pub unsafe fn get_current_directory() -> String {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	handle_unicode_string((*(*peb_ptr).ProcessParameters).CurrentDirectory.DosPath)
}


// The niceties:

/// Returns the computer name by reading `USERDOMAIN` environment variable
pub fn get_computer_name() -> String {
	get_environment_var("USERDOMAIN").unwrap()
}


/// Returns the current username by reading `USERNAME` environment variable
pub fn get_username() -> String {
	get_environment_var("USERNAME").unwrap()
}


/// Returns the path to tmp directory by reading `TEMP` environment variable
pub fn get_temp() -> String {
	get_environment_var("TEMP").unwrap()
}


/// Returns the path to %APPDATA% by reading `APPDATA` environment variable
pub fn get_appdata() -> String {
	get_environment_var("APPDATA").unwrap()
}


/// Returns the path to windows directory by reading `windir` environment variable
pub fn get_windir() -> String {
	get_environment_var("windir").unwrap()
}


/// Reads the current process ID from the Thread Environment Block
pub fn get_process_id() -> u64 {
	let tib = get_teb_address();
	unsafe { (*tib).ClientId.UniqueProcess as u64 }
}


/// Reads the current thread ID from the Thread Environment Block
pub fn get_thread_id() -> u64 {
	let tib = get_teb_address();
	unsafe { (*tib).ClientId.UniqueThread as u64 }
}


