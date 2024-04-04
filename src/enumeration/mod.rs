pub mod processes;


/// Reads the current process's command line from the Process Environment Block.
///
/// # Safety  
/// This function is unsafe because it relies on the correct structure of the Process Environment Block.  
///  
/// # Returns  
/// Returns a vector containing every environment variables as `String` (with the format "KEY=value")
pub unsafe fn get_environment() -> Vec<String> {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	let length = (*(*peb_ptr).process_parameters).environment_size as usize / 2;
	let env_ptr = (*(*peb_ptr).process_parameters).environment;

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
/// # Safety  
/// This function is unsafe because it relies on the correct structure of the Process Environment Block.  
///  
/// # Returns  
/// The command line as a `String`
pub unsafe fn get_command_line() -> String {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	(*(*peb_ptr).process_parameters).command_line.to_string()
}


/// Returns the current working directory of the process from the Process Environment Block.
///
/// # Safety  
/// This function is unsafe because it relies on the correct structure of the Process Environment Block.  
///  
/// # Returns  
/// The current working directory as a `String`
pub unsafe fn get_current_directory() -> String {
	let peb_ptr = thermite::peb_walk::get_peb_address();
	(*(*peb_ptr).process_parameters).current_directory.dos_path.to_string()
}


// Always nice to have those:
pub fn get_computer_name() -> String {
	get_environment_var("USERDOMAIN").unwrap()
}


pub fn get_username() -> String {
	get_environment_var("USERNAME").unwrap()
}


pub fn get_temp() -> String {
	get_environment_var("TEMP").unwrap()
}


pub fn get_appdata() -> String {
	get_environment_var("APPDATA").unwrap()
}


pub fn get_windir() -> String {
	get_environment_var("windir").unwrap()
}

