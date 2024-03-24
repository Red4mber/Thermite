#![feature(pointer_byte_offsets)]


use std::ffi::c_void;

use crate::peb::*;

mod peb;

use std::arch::asm;
use std::ptr;

unsafe fn get_peb() -> PEB {
    let peb_ptr: *const PEB;
    asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
    ptr::read_unaligned(peb_ptr)
}
unsafe fn get_module_base_address(module_name: &str) -> Option<*const c_void> {
    let peb = get_peb();
    let last_module = (*peb.Ldr).InMemoryOrderModuleList.Blink;
    let mut module_entry: *mut LIST_ENTRY = (*peb.Ldr).InMemoryOrderModuleList.Flink;
    let mut module_base: *const LDR_DATA_TABLE_ENTRY;

    loop {
        module_base = module_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;
        println!("[?-?] Module : {}", (*module_base).BaseDllName);
        if (*module_base).BaseDllName.to_string().eq_ignore_ascii_case( module_name ) {
            println!("[^-^] Module Found at address : {:x?}", (*module_base).DllBase);
            return Some((*module_base).DllBase);
        }
        if module_entry == last_module {
            eprintln!("[TwT] Module not found !");
            return None
        }

        module_entry = (*module_entry).Flink;
    }
}


fn main() {
    unsafe {
        let _ntdll_base = get_module_base_address("ssss.dll");


    }
}

