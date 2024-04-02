

use std::ptr;
use thermite::debug;

pub mod direct;
pub mod indirect;

use crate::error::DllParserError;
use crate::info;
use crate::models::{Export, Syscall};
use crate::peb_walk::{get_all_exported_functions, get_function_address, get_module_address};


/// Reads the syscall number from a syscall stub.
///
/// Iterates over the bytes of the syscall stub to find the pattern :
/// `[0x4c, 0x8b, 0xd1, 0xb8, ssn_1, ssn_2, 0x00, 0x00]`
///
/// If the pattern matches, we join the two bytes together and return the SSN
///
/// If we don't find these bytes, it's either not a valid syscall address, either it has been hooked
/// We cannot recover the SSN so we just return None
///
/// # Arguments
///
/// - `syscall_addr` : The address of the function we are looking for, can be obtained with [`get_function_address`]
///
pub fn find_ssn(addr: *const u8) -> Option<u16> {
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
pub unsafe fn halos_gate(addr: *const u8) -> Option<u16> {
    for i in 1..500 {
        let up = find_ssn(addr.byte_offset(32 * i));
        if up.is_some() {
            let ssn = up.unwrap() - i as u16;
            info!("Found clean syscall {} functions up at address {:x?}!", i, addr);
            return Some(ssn)
        }
        let down = find_ssn(addr.byte_offset(-32 * i));
        if down.is_some() {
            let ssn = down.unwrap() + i as u16;
            info!("Found clean syscall {} functions down at address {:x?} !", i, addr);
            return Some(ssn)
        }
    }
    None
}


/// Searches for every syscalls using the provided pattern
/// It then executes the find_ssn function on every one of them to retrieve their syscall numbers
///
/// Returns a vector of [Syscall] containing the matches
///
pub fn search(
    filter_fn: fn(&&Export) -> bool,
    find_ssn: fn(*const u8) -> Option<u16>,
) -> Result<Vec<Syscall>, DllParserError> {
    let ntdll_handle = unsafe { get_module_address("ntdll.dll") }?;
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
    return Ok(result);
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
pub unsafe fn find_single_ssn(name: &str) -> Option<u16> {
    let func_ptr = get_function_address(
        name, get_module_address("ntdll.dll").unwrap()
    ).expect("Function not found in the export table");
    find_ssn(func_ptr)
}


