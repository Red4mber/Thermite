use std::ptr;

use crate::error::DllParserError;
use crate::info;
use crate::peb_walk::{ExportedFunction, get_all_exported_functions, get_function_address, get_module_handle};


pub mod direct;
pub mod indirect;






/// Represents a syscall, we mostly only need the name and System Service Number
/// Each [Syscall] struct contains the following fields:
///
/// * `name` - The name of the corresponding function function in Ntdll (`String`).
/// * `address` - The address of the corresponding function in Ntdll (`*const u8`).
/// * `ssn` - The ID of the syscall (`u16`).
#[derive(Debug, Clone)]
pub struct Syscall {
	pub name: String,
	pub address: *const u8,
	pub ssn: u16,
}

/// Reads the syscall number from a syscall stub.
///
/// # Summary
/// Iterates over the bytes of the syscall stub to find the pattern :
/// `[0x4c, 0x8b, 0xd1, 0xb8, ssn_1, ssn_2, 0x00, 0x00]`
/// If the pattern matches, we return the SSN
///
/// If the first byte of the syscall is a `JMP` instruction (`[0xe9]`), this syscall is hooked
/// so we call the [halos_gate] function to find the syscall ID using it's neighbors syscall ID.
///
/// If we don't find these bytes, it's probably not a valid syscall address
/// We cannot recover the SSN so we just return None
///
/// # Arguments
/// - `addr` : The address of the syscall in ntdll.dll, it can be obtained using [`get_function_address`]
///
/// # Safety
/// Behavior is undefined if the address provided does not correspond to a valid syscall address.
///
pub unsafe fn find_ssn(addr: *const u8) -> Option<u16> {
	match ptr::read(addr as *const [u8; 8]) {
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


/// Finds out a hooked syscall ID using other syscalls around it
///
/// # Summary
/// The function seeks its neighbors up and down until it finds one that is not hooked.
///
/// Then, subtract(or add, depending on the direction) the number of syscalls "hopped" to the ID of
/// this syscall to get the hooked syscall ID we needed.
///
/// This method only work if syscall are incrementally numbered, which should be the case on most windows versions.
///
/// # Safety
///
/// Behavior is undefined if the address provided does not correspond to a valid syscall address.
///
pub unsafe fn halos_gate(addr: *const u8) -> Option<u16> {
	for i in 1..500 {
		let up = find_ssn(addr.byte_offset(32 * i));
		if up.is_some() {
			let ssn = up.unwrap() - i as u16;
			info!("Found clean syscall {} functions up at address {:x?}!", i, addr);
			return Some(ssn);
		}
		let down = find_ssn(addr.byte_offset(-32 * i));
		if down.is_some() {
			let ssn = down.unwrap() + i as u16;
			info!("Found clean syscall {} functions down at address {:x?} !", i, addr);
			return Some(ssn);
		}
	}
	None
}


/// Searches the export table of ntdll for syscalls using the provided matching function
///
/// It then executes the `find_ssn` function to filter syscalls
///
/// Returns a vector of [Syscall] containing the matches
///
pub fn search(
	filter_fn: fn(&&ExportedFunction) -> bool,
	find_ssn: fn(*const u8) -> Option<u16>,
) -> Result<Vec<Syscall>, DllParserError> {
	let ntdll_handle = unsafe { get_module_handle("ntdll.dll") }?;
	let result: Vec<Syscall> = unsafe { get_all_exported_functions(ntdll_handle) }?
		.iter()
		.filter(filter_fn)
		.filter_map(|x| {
			find_ssn(x.address).map(|ssn| Syscall {
				name: x.name.clone(),
				address: x.address,
				ssn,
			})
		})
		.collect();
	Ok(result)
}

// This macro takes in any two elements separated by a space replace them by the second one
// Despite what it sounds, it's actually a useful expansion used in `count_args`,
// it allows us to "consume" arguments to count them
#[macro_export]
macro_rules! replace_expr {
    ($_t:tt $sub:expr) => {
        $sub
    };
}

/// Macro that takes an arbitrary number of arguments and "returns" how many.
///
/// It is a macro not a function, so it doesn't actually return anything, but expands at compile time into the [`core::slice::len`] function, with an array
/// containing as many elements as there are arguments passed to the macro.
#[macro_export]
macro_rules! count_args {
    ($($args:expr),* $(,)?) => {
        {<[()]>::len(&[$($crate::replace_expr!($args ())),*])} as u32
    }
}


/// Helper function to find a single SSN from a syscall name
///
/// First finds the address of the ntdll.dll module
/// Then finds the function address in the exports table
/// Then tries to read the syscall number from the bytes of the function
/// 
/// ## Safety
/// So that clippy shuts up
/// I'll write better doc later  TODO
pub unsafe fn find_single_ssn(name: &str) -> Option<u16> {
	let func_ptr = get_function_address(
		name, get_module_handle("ntdll.dll").unwrap(),
	).expect("Function not found in the export table");
	find_ssn(func_ptr)
}


/// Retrieve every syscalls.
///

/// Get a list of every syscalls by searching Ntdll.dll for functions starting with "Nt", then sorts
/// the syscalls array by addresses and fill the syscalls IDs using their position in the list.
///
/// Returns a Vec<[Syscall]>
///
/// # Notes
/// This technique only works if the syscalls are incrementally numbered,
/// which should be the case on most windows versions.
///
pub fn get_ssns_by_sorting() -> Vec<Syscall> {
	// First we get an array of every function exported by ntdll starting with "Nt"
	let ntdll_handle = unsafe { get_module_handle("ntdll.dll") }.unwrap();
	let binding = unsafe { get_all_exported_functions(ntdll_handle) }.unwrap();
	let mut all_exports: Vec<&ExportedFunction> = binding
		.iter()
		.filter(|x1| x1.name.starts_with("Nt") && !x1.name.starts_with("Ntdll"))
		.collect();

	// We sort every function by its address
	all_exports.sort_by(|a, b| a.address.cmp(&b.address));
	// We then simply number every function
	return all_exports.iter().enumerate()
	                  .map(|(idx, &ex)| {
		                  Syscall {
			                  address: ex.address,
			                  name: ex.name.clone(),
			                  ssn: idx as u16,
		                  }
	                  }).collect();
}