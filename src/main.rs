#![feature(pointer_byte_offsets)]

extern crate memoffset; // For Debugging
use crate::peb::*;
mod peb;
use std::slice;
use std::ffi::OsString;

use std::arch::asm;
use std::os::windows::prelude::OsStringExt;
use std::ptr;
use memoffset::offset_of;
// use memoffset::offset_of;

unsafe fn get_peb_address() -> *const PEB {
    let peb_ptr;
    asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
    peb_ptr
}

fn read_peb() -> PEB {
    unsafe { ptr::read_unaligned(get_peb_address()) }
}


fn main() {
    unsafe {
        let peb_ptr: *const PEB;
        asm!("mov {}, gs:[0x60]", out(reg) peb_ptr);
        let peb = *get_peb_address();
        let first_link_address = (*peb.Ldr).InMemoryOrderModuleList.Flink;
        let load_module_ptr = first_link_address as *const LDR_DATA_TABLE_ENTRY;
        // let next_entry_ptr = ((*first_link).Flink -0x16) as *const LDR_DATA_TABLE_ENTRY;
        println!("[^-^] {}", (*load_module_ptr).BaseDllName);
        // let module = unsafe { std::mem::transmute<peb::LIST_ENTRY, LDR_MODULE>(first_entry); };
        // let next_link =  (*first_link).Flink;
        // let next_entry = (*first_link).Flink as *const LDR_DATA_TABLE_ENTRY;
        // println!("[^-^] {:#?}", *next_entry);




        // Expected Offset : 0x048
        // Observed Offset : 0x038
        // let debug_test = load_module_ptr.byte_offset(0x38) as *const UNICODE_STRING;
        // println!("[?-?] Offset 0x038 : {}", *debug_test);
        // println!("[?-?] LDR_DATA_TABLE_ENTRY Size : {:#x?}", std::mem::size_of::<LDR_DATA_TABLE_ENTRY>());
        // println!("[?-?] Void Ptr Size : {:#x?}", std::mem::size_of::<*const _>());



        // unsafe { print_unicode_string(&(*first_entry).BaseDllName); }
    }



    // println!("{:#x}", offset_of!(PEB, KernelCallbackTable));
    // println!("{:#x}", offset_of!(PEB, UserSharedInfoPtr));
    // println!("{:#x}", offset_of!(PEB, SessionId));
    // println!("{:#x}", offset_of!(PEB, ExtendedFeatureDisableMask));
    // println!("{:#x}", offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks));
    // println!("{:#x}", offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
    // println!("{:#x}", offset_of!(LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks));
    // println!("{:#x}", offset_of!(LDR_DATA_TABLE_ENTRY, DllBase));
    // println!("{:#x}", offset_of!(LDR_DATA_TABLE_ENTRY, EntryPoint));
    // println!("{:#x}", offset_of!(LDR_DATA_TABLE_ENTRY, SizeOfImage));
}


fn print_unicode_string(unicode_str: &UNICODE_STRING) {
    // First, check if the Buffer pointer is null
    if unicode_str.Buffer.is_null() {
        println!("The UNICODE_STRING is empty or invalid.");
        return;
    }

    // Create a slice from the Buffer pointer and the Length value
    let slice = unsafe {
        slice::from_raw_parts(unicode_str.Buffer, unicode_str.Length as usize)
    };

    // Convert the slice of u16 values to an OsString
    let os_string = OsString::from_wide(slice);

    // Print the OsString as a regular Rust string
    println!("{}", os_string.to_string_lossy());
}