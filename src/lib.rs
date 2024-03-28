#![feature(pointer_byte_offsets)]

use std::arch::asm;
use crate::model::windows::peb_teb::PEB;

pub mod model;
pub mod error;
pub mod dll_parser;

pub mod syscalls;


/// Helper function to get the address of the Process Environment Block (PEB).
///
/// # Safety
///
/// This function is deemed unsafe by the rust gods because it uses inline assembly.
/// However, it should be relatively safe to use, as this method is consistent.
///
/// # Returns
///
/// If the PEB address is successfully retrieved, returns `Some` with a pointer to the PEB.
/// If the PEB address somehow cannot be retrieved and returns a null pointer, it returns `None`.
///
/// # Notes
///
/// Only supports x86 or x86_64
///
/// This function uses inline assembly to retrieve the PEB address from the appropriate
/// Thread Environment Block (TEB) field based on the target architecture .
unsafe fn get_peb_address() -> Option<*const PEB> {
    #[inline(always)]
    fn read_peb_ptr() -> *const PEB {
        #[cfg(target_arch = "x86")]
        unsafe {
            let peb: *const PEB;
            asm!("mov eax, fs:[0x30]", out("eax") peb, options(nomem, nostack, preserves_flags));
            peb
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let peb: *const PEB;
            asm!("mov rax, gs:[0x60]", out("rax") peb, options(nomem, nostack, preserves_flags));
            peb
        }
    }

    let peb_ptr = read_peb_ptr();
    if peb_ptr.is_null() {
        None
    } else {
        Some(&*(peb_ptr))
    }
}



