use ntapi::ntapi_base::CLIENT_ID;
use winapi::um::minwinbase::EXCEPTION_SINGLE_STEP;
use winapi::um::winnt::{CONTEXT, CONTEXT_DEBUG_REGISTERS, HANDLE, PEXCEPTION_POINTERS, PVOID, THREAD_ALL_ACCESS};
use winapi::vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH};

use crate::enumeration::{get_process_id, get_thread_id};
use crate::error;
use crate::utils::get_empty_objectattributes;


struct BreakpointDescriptor {
	address: *const u8,
	position: DebugRegister,
	thread_id: u64,
	callback: *const fn()
}

static mut BREAKPOINTS: Vec<BreakpointDescriptor> = Vec::new();

// ENUMS
/// Represents the various flags and fields found in the DR7 register
/// Serves mostly as Bitmasks to make DR7 easier to configure
///
#[repr(u64)]
pub enum DR7 {
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

/// A breakpoint can trigger on Read, Write, Execute or I/O Read/Write
/// This is the value to put in the two conditions bits to have the desired effect
pub enum BreakConditions { Execute = 0, Write = 1, IO = 2, ReadWrite = 3 }

/// The four different registers available to put a breakpoint address in
#[derive(Debug, Clone, Copy)]
pub enum DebugRegister { DR0 = 0, DR1 = 1, DR2 = 2, DR3 = 3 }

/// Sets up a new breakpoint
///
/// Takes a debug register, the desired breakpoint address, a context and a function callback as argument.
/// - The debug register must be of type [DebugRegister]
/// - The address can be any valid address
/// - The callback function is a function pointer, it can be of any type, just cast it using `*const _`
/// - The thread ID mus be a valid thread ID
pub fn set_breakpoint(dr: DebugRegister, address: *const u8, callback: *const fn(), thread_id: u64) {
	let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	// If the thread ID isn't the current thread, we need to get a handle to the thread
	let mut thread_handle = -2isize as HANDLE;
	if thread_id != get_thread_id() {
		let cid = CLIENT_ID {
			UniqueProcess: get_process_id() as HANDLE,
			UniqueThread: thread_id as HANDLE,
		};
		crate::indirect_syscall!("NtOpenThread", &mut thread_handle, THREAD_ALL_ACCESS, get_empty_objectattributes(), cid);
	}

	let status = crate::indirect_syscall!("NtGetContextThread", thread_handle, &mut ctx);
	if status != 0 { error!(status); };

	println!("Setting up breakpoint {:?} for address {:?}", dr, address);
	match dr {
		DebugRegister::DR0 => {
			if ctx.Dr0 != 0 { error!("DR0 isn't empty !"); return; } else { ctx.Dr0 = address as u64 }
		},
		DebugRegister::DR1 => {
			if ctx.Dr1 != 0 { error!("DR1 isn't empty !"); return; } else { ctx.Dr1 = address as u64 }
		},
		DebugRegister::DR2 => {
			if ctx.Dr2 != 0 { error!("DR2 isn't empty !"); return; } else { ctx.Dr2 = address as u64 }
		},
		DebugRegister::DR3 => {
			if ctx.Dr3 != 0 { error!("DR3 isn't empty !"); return; } else { ctx.Dr3 = address as u64 }
		},
	};
	// Calculate which bits need to be turned on depending on the register
	let n: u64 = dr as u64;
	let l: u64 = n*2;               // Local breakpoints enable
	let len: u64 = 18+n*4;          // Length of address - only use 64bits so far, so 0b11
	ctx.Dr7 |= l|len|(len+1);       // combine flags we use in a mask - the local enable | address length 0b11
	ctx.Dr6 = 0;                    // Then zero DR6 for good figure

	let status = crate::indirect_syscall!("NtSetContextThread", thread_handle, &mut ctx);
	if status != 0 { error!(status); };

	unsafe {
		BREAKPOINTS.push(BreakpointDescriptor {
			address,
			position: dr,
			thread_id,
			callback,
		})
	}
}


/// Removes a breakpoint from the DR7 register
pub fn remove_breakpoint(dr: DebugRegister, ctx: &mut CONTEXT) {
	let mask: u64 = match dr {
		DebugRegister::DR0 => { ctx.Dr0 = 0x00; DR7::L0 as u64 | DR7::LEN0 as u64 | DR7::CND0 as u64 },
		DebugRegister::DR1 => { ctx.Dr1 = 0x00; DR7::L1 as u64 | DR7::LEN1 as u64 | DR7::CND1 as u64 },
		DebugRegister::DR2 => { ctx.Dr2 = 0x00; DR7::L2 as u64 | DR7::LEN2 as u64 | DR7::CND2 as u64 },
		DebugRegister::DR3 => { ctx.Dr3 = 0x00; DR7::L3 as u64 | DR7::LEN3 as u64 | DR7::CND3 as u64 },
	};
	ctx.Dr7 &= !mask;
	ctx.Dr6 = 0;
	ctx.EFlags = 0;

}

/// Zero all debug registers - removes all flags and addresses
pub fn remove_all_breakpoints(ctx: &mut CONTEXT) {
	ctx.Dr0 = 0;
	ctx.Dr1 = 0;
	ctx.Dr2 = 0;
	ctx.Dr3 = 0;
	ctx.Dr6 = 0;
	ctx.Dr7 = 0;
	ctx.EFlags = 0;
}



/// Searches a breakpoint with an address
///
/// Takes an address as argument, returns an option containing the register holding this address
/// Returns None if the address is not found in a debug register
pub fn search_breakpoint(address: PVOID, ctx: &CONTEXT) -> Option<DebugRegister> {
	if address as u64 == ctx.Dr0 { Some(DebugRegister::DR0) }
	else if address as u64 == ctx.Dr1 { Some(DebugRegister::DR1) }
	else if address as u64 == ctx.Dr2 { Some(DebugRegister::DR2) }
	else if address as u64 == ctx.Dr3 { Some(DebugRegister::DR3) }
	else { None }
}


#[allow(unused_mut)]
/// This is my vectored exception handler
///
/// It'll check that the exception originates from a breakpoint, then if it does, executes the corresponding callback
/// A  `&mut CONTEXT` is passed as argument to all callbacks
/// ### Safety
/// Yeah safety now clippy will shut the fuck up
pub unsafe extern "system" fn vectored_handler(mut exception_info: PEXCEPTION_POINTERS) -> i32 {
	unsafe {
		let rec = &(*(*exception_info).ExceptionRecord);
		let mut ctx = &mut (*(*exception_info).ContextRecord);

		if rec.ExceptionCode == EXCEPTION_SINGLE_STEP && search_breakpoint(rec.ExceptionAddress, ctx).is_some() {
			// info!("Successfully hooked o//");

			let callback = BREAKPOINTS.iter().filter_map(|x| {
				if x.thread_id == get_thread_id() && x.address == rec.ExceptionAddress as *const u8 {
					return Some(std::mem::transmute::<*const fn(), fn(&mut CONTEXT)>(x.callback));
				}
				return None;
			}).next().unwrap(); // TODO: UGLY UNWRAP

			callback(ctx);


			return EXCEPTION_CONTINUE_EXECUTION;
		}
		EXCEPTION_CONTINUE_SEARCH
	}
}

/// Reads the arguments passed to the hooked function by reading the context's registers
pub fn get_arguments(ctx: &CONTEXT, idx: i32) -> u64 {
	match idx {
		0 => ctx.Rcx,
		1 => ctx.Rdx,
		2 => ctx.R8,
		3 => ctx.R9,
		_ => unsafe { *( (ctx.Rsp as *const u64).offset((idx + 1) as isize) ) }
	}
}

pub fn set_ret_value(value: u64, ctx: &mut CONTEXT) { ctx.Rax = value; }

pub fn set_resume_flag(ctx: &mut CONTEXT) { ctx.EFlags |= 1<<16; }

pub fn rip_to_return_address(ctx: &mut CONTEXT) {
	unsafe { ctx.Rip = *(ctx.Rsp as *const u64); }
	ctx.Rsp += std::mem::size_of::<*const u64>() as u64;
}
