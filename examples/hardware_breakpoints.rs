#![allow(unused)]

use std::ffi::{c_void, CString};
use std::ptr::null_mut;

use ntapi::ntpsapi::{NtGetContextThread, NtSetContextThread};
use ntapi::ntpsapi::NtCurrentThread;
use widestring::WideStr;
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::NULL;
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::{AddVectoredExceptionHandler, RemoveVectoredExceptionHandler};
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::minwinbase::EXCEPTION_SINGLE_STEP;
use winapi::um::winnt::{CONTEXT, CONTEXT_ALL, HANDLE, LPCSTR, LPCWSTR, PCONTEXT, PCSTR, PEXCEPTION_POINTERS, PVOID};
use winapi::um::winuser;
use winapi::um::winuser::{MB_OK, MessageBoxA, MessageBoxW};

use thermite::{debug, error, indirect_syscall as syscall, info};
use thermite::peb_walk::{get_function_address, get_module_address, get_teb_address};

use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION,EXCEPTION_CONTINUE_SEARCH};


static mut HOOKED_FUNCTION: *mut u8 = null_mut();


#[repr(u64)]
enum BitMasks {
	  L0 = (1<<0),          // Local Enable #0
	  G0 = (1<<1),          // Global Enable #0
	  L1 = (1<<2),          // Local Enable #1
	  G1 = (1<<3),          // Global Enable #1
	  L2 = (1<<4),          // Local Enable #2
	  G2 = (1<<5),          // Global Enable #2
	  L3 = (1<<6),          // Local Enable #3
	  G3 = (1<<7),          // Global Enable #3
	  GD = (1<<13),         // General detection enable
	CND0 = (1<<16)|(1<<17), // Breakpoint condition #0
	LEN0 = (1<<18)|(1<<19), // Address Length #0
	CND1 = (1<<20)|(1<<21), // Breakpoint condition #1
	LEN1 = (1<<22)|(1<<23), // Address Length #1
	CND2 = (1<<24)|(1<<25), // Breakpoint condition #2
	LEN2 = (1<<26)|(1<<27), // Address Length #2
	CND3 = (1<<28)|(1<<29), // Breakpoint condition #3
	LEN3 = (1<<30)|(1<<31), // Address Length #3
}



enum BreakConditions { Execute = 0, Write = 1, IO = 2, ReadWrite = 3 }

#[derive(Debug, Clone, Copy)]
enum DebugRegister { DR0 = 0, DR1 = 1, DR2 = 2, DR3 = 3 }

#[allow(overflowing_literals)]
fn status_to_string(status: i32) -> String {
	match status {
		0 => { "Success o/".to_string() },
		0x80000002 => { "Datatype Misalignment".to_string() },
		0xC0000005 => { "Access Denied".to_string() },
		0xC0000409 => { "Buffer Overrun".to_string() },
		_ => { format!("unknown oopsie: {:x?}", status).to_string() }
	}
}
//
// fn get_context(ctx: PCONTEXT) -> CONTEXT {
// 	let nt_status = unsafe { NtGetContextThread(NtCurrentThread, ctx) };
// 	unsafe { *ctx }
// }
//
// fn set_context(ctx: PCONTEXT) -> i32 {
// 	let nt_status = unsafe { NtSetContextThread(NtCurrentThread, ctx) };
// 	nt_status
// }

fn set_breakpoint(dr: DebugRegister, address: *mut u8, ctx: &mut CONTEXT) {
	println!("Setting up breakpoint {:?} for address {:?}", dr, address);
	let mask: u64 = match dr {
		DebugRegister::DR0 => {
			if ctx.Dr0 == 0 {
				ctx.Dr0 = address as u64;
				BitMasks::L0 as u64 | BitMasks::LEN0 as u64
			} else { error!("DR0 Register isn't empty !"); return; }
		},
		DebugRegister::DR1 => {
			if ctx.Dr1 == 0 {
				ctx.Dr1 = address as u64;
				BitMasks::L1 as u64 | BitMasks::LEN1 as u64
			} else { error!("DR1 Register isn't empty !"); return; }
		},
		DebugRegister::DR2 => {
			if ctx.Dr2 == 0 {
				ctx.Dr2 = address as u64;
				BitMasks::L2 as u64 | BitMasks::LEN2 as u64
			} else { error!("DR2 Register isn't empty !"); return; }
		},
		DebugRegister::DR3 => {
			if ctx.Dr3 == 0 {
				ctx.Dr3 = address as u64;
				BitMasks::L3 as u64 | BitMasks::LEN3 as u64
			} else { error!("DR3 Register isn't empty !"); return; }
		},
	};
	ctx.Dr7 |= mask;
	ctx.Dr6 = 0;

}

fn remove_breakpoint(dr: DebugRegister, ctx: &mut CONTEXT) {
	let mask: u64 = match dr {
		DebugRegister::DR0 => { ctx.Dr0 = 0x00; BitMasks::L0 as u64 | BitMasks::LEN0 as u64 },
		DebugRegister::DR1 => { ctx.Dr1 = 0x00; BitMasks::L1 as u64 | BitMasks::LEN1 as u64 },
		DebugRegister::DR2 => { ctx.Dr2 = 0x00; BitMasks::L2 as u64 | BitMasks::LEN2 as u64 },
		DebugRegister::DR3 => { ctx.Dr3 = 0x00; BitMasks::L3 as u64 | BitMasks::LEN3 as u64 },
	};
	// debug!(mask);
	ctx.Dr7 &= !mask;
	// debug!(ctx.Dr0,ctx.Dr1,ctx.Dr2,ctx.Dr3,ctx.Dr7);
}

fn remove_all_breakpoints(ctx: &mut CONTEXT) {
	ctx.Dr0 = 0;
	ctx.Dr1 = 0;
	ctx.Dr2 = 0;
	ctx.Dr3 = 0;
	ctx.Dr6 = 0;
	ctx.Dr7 = 0;
	ctx.EFlags = 0;
}

fn search_breakpoint(address: PVOID, ctx: &CONTEXT) -> Option<DebugRegister> {
	if address as u64 == ctx.Dr0 { Some(DebugRegister::DR0) }
	else if address as u64 == ctx.Dr1 { Some(DebugRegister::DR1) }
	else if address as u64 == ctx.Dr2 { Some(DebugRegister::DR2) }
	else if address as u64 == ctx.Dr3 { Some(DebugRegister::DR3) }
	else { None }
}

fn test() {
	println!("This is a test :D")
}

fn main() {
	let handler = unsafe { AddVectoredExceptionHandler(1, Some(vectored_handler)) };
	if handler.is_null() {
		error!("Failed to add exception handler");
		std::process::exit(-1)
	} else { info!("Successfully added exception handler, handle : {:?}", handler); }

	unsafe {
		let user32 = LoadLibraryA(CString::new("User32.dll").unwrap().as_ptr());

		let messageboxa_address = get_function_address("MessageBoxA", user32 as _).unwrap();
		HOOKED_FUNCTION = messageboxa_address as _;
	}


	let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
	ctx.ContextFlags = CONTEXT_ALL;

	unsafe {
		let status = NtGetContextThread(NtCurrentThread, &mut ctx);
		if status != 0 { debug!(status); };
		set_breakpoint(DebugRegister::DR0, HOOKED_FUNCTION, &mut ctx);

		let status = NtSetContextThread(NtCurrentThread, &mut ctx);
		if status != 0 { debug!(status); };
	};

	unsafe {
		MessageBoxA(
			0 as _,
			0 as _,
			0 as _,
			0
		);
	}
	let ret = unsafe { RemoveVectoredExceptionHandler(handler) };
	if ret == 0 { error!("Failed to remove exception handler") }
}

unsafe extern "system" fn vectored_handler(mut exception_info: PEXCEPTION_POINTERS) -> i32 {
	unsafe {
		let rec = &(*(*exception_info).ExceptionRecord);
		let ctx = &mut (*(*exception_info).ContextRecord);

		if rec.ExceptionCode == EXCEPTION_SINGLE_STEP && rec.ExceptionAddress == HOOKED_FUNCTION as PVOID {
			info!("Successfully hooked o//");

			// ctx.Dr7 = 0;
			// ctx.Dr0 = 0;
			// // NtSetContextThread(NtCurrentThread, ctx);

			debug!(ctx.Dr0, ctx.Dr7);

			hook();

			// set_breakpoint(DebugRegister::DR0, HOOKED_FUNCTION, ctx);
			// NtSetContextThread(NtCurrentThread, ctx);
			// debug!(ctx.Dr0, ctx.Dr7);

			return EXCEPTION_CONTINUE_EXECUTION;
		} else {
			debug!("not the breakpoint");
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

unsafe fn hook() {
	println!("This is the hook");
	MessageBoxW(
		0 as _,
		"HOOK\0".encode_utf16().collect::<Vec<_>>().as_ptr(),
		0 as _,
		0
	);
}

