// #![feature(half_open_range_patterns_in_slices)]
use std::ptr;
use thermite::{debug, error, info};
use thermite::models::{Export, Syscall};
use thermite::peb_walk::{get_all_exported_functions, get_function_address, get_module_address};
use thermite::syscalls::{search};


// I don't have a hooked ntdll.dll to test it right now, so let's just deny some addresses manually
// I'll deny 500 bytes around NtOpenProcess
// Yea it's ugly, but whatever, it's only for debugging
unsafe fn deny_addresses(addr: *const u8) -> Option<*const u8> {
	let ntdll_address = get_module_address("ntdll.dll").unwrap();
	let denied = get_function_address("NtOpenProcess", ntdll_address).unwrap();
	if addr.offset_from(denied) <= 500 {
		error!("{:#x?} is denied !", addr);
		return None;
	}
	return Some(addr);
}


// Check if we can find a SSN in this function
pub fn find_ssn(addr: *const u8) -> Option<u16> {
	unsafe { if deny_addresses(addr).is_none() { return None } }       // For test purposes only
	match unsafe { ptr::read(addr as *const [u8; 8]) } {
		// Begins with JMP => Probably hooked
		[0xe9, ..] => {
			return unsafe { halos_gate(addr) };
		},
		[0x4c, 0x8b, 0xd1, 0xb8, ssn_1, ssn_2, 0x00, 0x00] => {
			let ssn = ((ssn_2 as u16) << 8) + ssn_1 as u16;
			return Some(ssn);
		}
		_ => {}
	}

	None
}

/// If a syscall is hooked, seek up and down until it finds a clean syscall
/// Then subtract(or add, depending on the direction) the number of functions hopped to get the ssn
/// This method only work if syscall are incrementally numbered
unsafe fn halos_gate(addr: *const u8) -> Option<u16> {
	find_ssn(addr).or_else(|| {
		for i in 1..500 {
			let up = find_ssn(addr.byte_offset(32 * i)).and_then(|up| {
				up.unwrap() - i as u16
			});
			if up.is_some() { return up }
			let down = find_ssn(addr.byte_offset(-32 * i)).and_then(|down| {
				down.unwrap() + i as u16
			});
			if down.is_some() { return down }
		}
		None
	})
}


fn main() {
	unsafe {
		// Get the address of ntdll
		let ntdll_address = unsafe { get_module_address("ntdll.dll") }.unwrap();

		// Parse the export table to find our function
		let addr = get_function_address("NtOpenProcess", ntdll_address).unwrap();

		debug!(halos_gate(addr));
	}
}