#![feature(pointer_byte_offsets)] // I should find a way to do without
///////////////////////////////////////////////////////////
//
//             -- Thermite: Offensive Rust --
//                   Main Library File
//
//          Made by RedAmber - 27 March 2024
///////////////////////////////////////////////////////////

use std::arch::asm;
use crate::model::peb_teb::PEB;

pub mod model;
pub mod error;
pub mod exports;


/// Helper function to get the address of the Process Environment Block (PEB).
///
/// # Safety
///
/// This function performs unsafe operations and assumes the presence and validity of various
/// Windows structures and memory layouts. It should only be called in a context where these
/// assumptions are valid.
///
/// # Returns
///
/// If the PEB address is successfully retrieved, returns `Some` with a pointer to the PEB.
/// If the PEB address cannot be retrieved, returns `None`.
///
/// # Notes
///
/// This function uses inline assembly to retrieve the PEB address from the appropriate Thread
/// Environment Block (TEB) field based on the target architecture (x86 or x86_64).
///
/// The Process Environment Block (PEB) is a user-mode data structure that contains essential
/// information about the current process, including various data structures and lists that
/// describe the modules loaded into the process's virtual address space.
unsafe fn get_peb_address() -> Option<*const PEB> {
    #[inline(always)]
    fn peb_pointer() -> *const PEB {
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

    let peb_pointer = peb_pointer();
    if peb_pointer.is_null() {
        None
    } else {
        Some(&*(peb_pointer))
    }
}



