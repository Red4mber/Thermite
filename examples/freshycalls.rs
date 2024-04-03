use thermite::{debug, error, info};
use thermite::models::{Export, Syscall};
use thermite::peb_walk::{get_all_exported_functions, get_function_address, get_module_address};
use thermite::syscalls::find_ssn;

/* This example is a demonstration of FreshyCalls's technique to retrieve hooked syscall IDs.

Since on most versions of windows, all syscalls are in order, we can easily derive the syscall ID from their addresses.
We only need to find every syscalls and sort our list of syscalls using their addresses.
When this is done, we can observe that all the SSNs are in order as well.

As a demonstration i created a second array that i populated using data from our usual find_ssn() function,
to make sure the SSN we found we all valid, and lo and behold, they all were.
*/

fn main() {
	// First we get an array of every function exported by ntdll starting by "Nt"
	let ntdll_handle = unsafe { get_module_address("ntdll.dll") }.unwrap();
	let binding = unsafe { get_all_exported_functions(ntdll_handle) }.unwrap();
	let mut all_exports: Vec<&Export> = binding
		.iter()
		.filter(|x1| x1.name.starts_with("Nt") && !x1.name.starts_with("Ntdll"))
		.collect();

	// We sort every function by its address
	all_exports.sort_by(|a, b| a.address.cmp(&b.address));
	// We then simply number every function
	let guessed_syscalls: Vec<Syscall> =
		all_exports.iter().enumerate()
		           .map(|(idx, &ex)| {
			           Syscall {
				           address: ex.address,
				           name: ex.name.clone(),
				           ssn: idx as u16,
			           }
		           }).collect();
	// Because SSNs are numbered incrementally, they should all have the correct SSN


	// Let get a control array, numbered using our "find_ssn" function, as usual
	let verif_binding = unsafe { get_all_exported_functions(ntdll_handle) }.unwrap();
	let verif_all_exports: Vec<&Export> = verif_binding
		.iter()
		.filter(|x1| x1.name.starts_with("Nt") && !x1.name.starts_with("Ntdll"))
		.collect();
	let mut control: Vec<Syscall> = verif_all_exports.iter().filter_map(|x| {
		find_ssn(x.address).map(|ssn| Syscall {
			name: x.name.clone(),
			address: x.address,
			ssn,
		})
	}).collect();
	// We sort the control array by address too
	control.sort_by(|a, b| a.address.cmp(&b.address));


	// Now we can check that the two arrays are the exact same,
	// using zip we iterate over the two arrays simultaneously
	// Using filter_map, we keep only those who aren't correct, then print is using error
	// If everything goes well, we should see any errors o/
	let _: Vec<_> = guessed_syscalls.iter().zip(control.iter_mut()).filter_map(|(x1, &mut ref x2)| {
		x1.ssn.ne(&x2.ssn).then(|| (x1, x2))
	}).map(|x| error!("{:#x?}", x)).collect();
}
