use std::ffi::CString;

use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::winnt::{CONTEXT, CONTEXT_ALL, CONTEXT_DEBUG_REGISTERS};
use winapi::um::winuser::MessageBoxA;

use thermite::{debug, error, indirect_syscall as syscall, info};
use thermite::breakpoints::{DebugRegister, set_breakpoint, vectored_handler};
use thermite::enumeration::get_thread_id;
use thermite::peb_walk::get_function_address;


fn main() {
	// Adding the vectored_handler  provided by the thermite::breakpoints module
	let handler = unsafe { AddVectoredExceptionHandler(1, Some(vectored_handler)) };
	if handler.is_null() {
		error!("Failed to add exception handler");
		std::process::exit(-1)
	}
	
	// Loading a DLL to hook a function
	// Here we target MessageBoxA as example
	let messageboxa_address: *const u8;
	unsafe {
		let libname = CString::new("User32.dll");
		let user32 = LoadLibraryA(libname.unwrap().as_ptr());

		messageboxa_address = get_function_address("MessageBoxA", user32 as _).unwrap();
	} // i'm using my own getprocadress nut i don't have a custom implementation of loadlibrary yet
	
	debug!(messageboxa_address, MessageBoxA as *const u8);
	
	
	// Now that we have the address of a function to target, let's set a breakpoint
	unsafe { set_breakpoint(DebugRegister::DR0, messageboxa_address, hook as _, get_thread_id()); };

	// Calling MessageBoxA now should call our hook instead
	unsafe {
		MessageBoxA(
			0 as _,
			"NOT THE HOOK\0".as_ptr() as _,
			0 as _,
			0
		);
		// If everything went well, there was no messagebox, but instead a 	println!("This is the hook");
		// The hook is still active for the current thread, we can leave it until we quit the program, or remove it using "remove_breakpoint" or "remove_all_breakpoints"
	}
	info!("We back to main o/");
	
	// We do need to remove the exception handler tho
	// Because this one is gonna stay even if the thread is no more
	// This can (and will) cause issues
	let ret = unsafe { RemoveVectoredExceptionHandler(handler) };
	if ret == 0 { error!("Failed to remove exception handler") }
}

fn hook(ctx: &mut CONTEXT) {
	println!("This is the hook");

	// Getting the return address of the hooked function and changing its instruction pointer to it, 
	// this should prevent the execution of the function, even if we set the resume flag to 1
	unsafe { ctx.Rip = *(ctx.Rsp as *const u64); }
	// But we do have to correct the stack pointer, else we're gonna overflow the stack
	ctx.Rsp += std::mem::size_of::<*const u64>() as u64;
	

	// We set the resume flag to 1, Allowing the hooked function to resume execution
	// But it wont, since we changed its Rip 
	// See : http://www.c-jump.com/CIS77/ASM/Instructions/I77_0070_eflags_bits.htm
	ctx.EFlags |= 1<<16;
}

