#![allow(nonstandard_style)]
// This place is not a place of honor...
// no highly esteemed deed is commemorated here...
// nothing valued is here.

use std::ffi::c_void;

use crate::models::windows::peb_teb::UNICODE_STRING;

/// Stuff to deal with the PEB and TEB structures in windows
/// Rather incomplete but also the less used of the two
pub mod peb_teb;

/// All the data structures used to parse DLLs
/// Really the only one of the two modules which is at least a little bit useful
pub mod pe_file_format;

// A single enum with 3000 variants to match NT_STATUS to actual legible errors
pub mod nt_status;
pub mod system_info;

// MASSIVE TODO: Clean up all these modules and remove everything unused
// Todo two : Reformat / Refactor both modules to respect rusts naming convention and make it easier to read

// I put the most common/useful stuuctures and constants here, so to use them i just have to do a
// use thermite::models::windows::*;
//
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_COMMIT: u32 = 0x1000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_READ: u32 = 0x20;

pub const SYNCHRONIZE: u32 = 0x00100000u32;
pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x00100000u32;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_ALL_ACCESS: u32 = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF;
pub const GENERIC_EXECUTE: u32 = 0x20000000;
pub const PROCESS_VM_READ: u32 = 0x0010;
// Required to read memory in a process using ReadProcessMemory.
pub const PROCESS_VM_WRITE: u32 = 0x0020;       // Required to write to memory in a process using WriteProcessMemory.


// Some types that i just left around and i'm now too lazy to clean it up
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;


// The magic handles o//
pub const NtCurrentProcess: HANDLE = -1isize as *mut c_void;
pub const NtCurrentThread: HANDLE = -2isize as *mut c_void;
pub const NtCurrentSession: HANDLE = -3isize as *mut c_void;
pub const NtCurrentProcessToken: HANDLE = -4isize as *mut c_void;
pub const NtCurrentThreadToken: HANDLE = -5isize as *mut c_void;
pub const NtCurrentEffectiveToken: HANDLE = -6isize as *mut c_void;


#[repr(C)]
pub struct ClientId {
	pub unique_process: isize,
	pub unique_thread: isize,
}

#[repr(C)]
pub struct ObjectAttributes {
	pub length: u32,
	pub root_directory: isize,
	pub object_name: *const UNICODE_STRING,
	pub attributes: u32,
	pub security_descriptor: *const c_void,
	pub security_quality_of_service: *const c_void,
}

impl Default for ObjectAttributes {
	fn default() -> ObjectAttributes {
		ObjectAttributes {
			length: std::mem::size_of::<ObjectAttributes>() as _,
			root_directory: 0u32 as _,
			object_name: 0u32 as _,
			attributes: 0,
			security_descriptor: 0u32 as _,
			security_quality_of_service: 0u32 as _,
		}
	}
}