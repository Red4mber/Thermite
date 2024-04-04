// #![feature(half_open_range_patterns_in_slices)]
use std::ptr;

use thermite::{debug, error};
use thermite::peb_walk::{get_function_address, get_module_address};



// To avoid requiring a hooked ntdll to test this method, i created this function to deny all addresses
// 500 bytes around the NtOpenProcess function.
// This force our find_ssn function to go seek the syscall ID further.
unsafe fn deny_addresses(addr: *const u8) -> Option<*const u8> {
	let ntdll_address = get_module_address("ntdll.dll").unwrap();
	let denied = get_function_address("NtOpenProcess", ntdll_address).unwrap();
	if addr.offset_from(denied) <= 500 {
		error!("{:#x?} is denied !", addr);
		return None;
	}
	Some(addr)
}


// Check if we can find a SSN in this function
unsafe fn find_ssn(addr: *const u8) -> Option<u16> {
	deny_addresses(addr)?;      // For test purposes only
	match ptr::read(addr as *const [u8; 8]) {
		// Begins with JMP => Probably hooked
		[0xe9, ..] => {
			return halos_gate(addr);
		}
		[0x4c, 0x8b, 0xd1, 0xb8, ssn_1, ssn_2, 0x00, 0x00] => {
			let ssn = ((ssn_2 as u16) << 8) + ssn_1 as u16;
			return Some(ssn);
		}
		_ => {}
	}
	None
}


/// Seeks up and down until it finds a clean syscall
/// Then subtract(or add, depending on the direction) the number of functions hopped to get the ssn
/// This method only work if syscall are incrementally numbered
unsafe fn halos_gate(addr: *const u8) -> Option<u16> {
	find_ssn(addr).or_else(|| {
		for i in 1..500 {
			let up = find_ssn(addr.byte_offset(32 * i)).map(|up| up - i as u16);
			if up.is_some() { return up; }
			let down = find_ssn(addr.byte_offset(-32 * i)).map(|down| down + i as u16);
			if down.is_some() { return down; }
		}
		None
	})
}


fn main() {
	unsafe {
		// Get the address of ntdll
		let ntdll_address = get_module_address("ntdll.dll").unwrap();

		// Parse the export table to find our function
		let addr = get_function_address("NtOpenProcess", ntdll_address).unwrap();

		debug!(halos_gate(addr));
	}
}