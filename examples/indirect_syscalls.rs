use std::ptr;
use thermite::{debug, syscalls};
use thermite::models::{Export, Syscall};
use thermite::peb_walk::{get_all_exported_functions, get_module_address};



pub unsafe fn find_syscall_address(addr: *const u8) -> Option<*const u8> {
	let syscall_ptr = addr.byte_offset(18);
	match unsafe { ptr::read(syscall_ptr as *const [u8; 2]) } {
		[0x0f, 0x05] => { Some(syscall_ptr) },
		_ => {None}
	}
}



// Check if we can find a SSN in this function
pub fn find_ssn(addr: *const u8) -> Option<u16> {
	match unsafe { ptr::read(addr as *const [u8; 8]) } {
		// Begins with JMP => Probably hooked
		[0xe9, ..] => {
			return unsafe { thermite::syscalls::halos_gate(addr) };
		},
		[0x4c, 0x8b, 0xd1, 0xb8, ssn_1, ssn_2, 0x00, 0x00] => {
			let ssn = ((ssn_2 as u16) << 8) + ssn_1 as u16;
			return Some(ssn);
		}
		_ => {}
	}
	None
}

fn main() {
	let ntdll_handle = unsafe { get_module_address("ntdll.dll") }.unwrap();
	let verif_binding = unsafe { get_all_exported_functions(ntdll_handle) }.unwrap();
	let verif_all_exports: Vec<&Export> = verif_binding
		.iter()
		.filter(|x1| x1.name.starts_with("Nt") && !x1.name.starts_with("Ntdll"))
		.collect();
	let all_syscalls: Vec<Syscall> = verif_all_exports.iter().filter_map(|x| {
		thermite::syscalls::find_ssn(x.address).map(|ssn| Syscall {
			name: x.name.clone(),
			address: x.address,
			ssn,
		})
	}).collect();

	// Get a syscall instruction address

	let mut iter = all_syscalls.iter().skip_while(|x2| unsafe { find_syscall_address(x2.address) }.is_none());
	let syscalls_address = unsafe { find_syscall_address(iter.next().unwrap().address); };

}