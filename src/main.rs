#![allow(unused)]


use thermite::dll_parser::{get_module_address, get_function_address, get_all_exported_functions, Export, get_all_loaded_modules};
use thermite::error::DllParserError;
use thermite::syscalls::simple_get_ssn;

// This file is really only there for testing, hence why all the comments and the unused functions
// It's just useful to have something to run

fn main() {
    // let module_addr = unsafe { get_module_address("ntdll.dll") }.unwrap_or_else(|err| {
    //     eprintln!("[TwT] {:#?}", err);
    //     std::process::exit(1)
    // });
    // example_get_function_address("ntdll.dll", "NtOpenProcess");
    // example_all_exports();
    test_syscall();
    // let all_modules = unsafe { get_all_loaded_modules() }.unwrap();
    // println!("[^-^] Loaded Modules : {:#?}", all_modules);


    // let syscall_name = "NtOpenProcess";
    // let syscall_addr = unsafe { get_function_address(syscall_name, module_addr) }.unwrap();
}


// Below are testing / example functions
// I will move them eventually but i'm still working on it
//
fn example_all_exports() {

    let module_address = unsafe { get_module_address("ntdll.dll") }.unwrap_or_else(|err| {
        eprintln!("[TwT] {:#?}", err);
        std::process::exit(1)
    });

    let mut exported_functions: Vec<Export> = unsafe { get_all_exported_functions(module_address) }.unwrap_or_else(|err: DllParserError| {
         eprintln!("[TwT] {:#?}", err);
         std::process::exit(1)
    });

    // Some usage examples :
    // Sort alphabetically by function name
    exported_functions.sort_by(|a, b| { a.name.to_lowercase().cmp(&b.name.to_lowercase()) });

    // Sort by address name
    exported_functions.sort_by(|a, b| { a.address.cmp(&b.address) });

    println!("[^-^] {:#?}", exported_functions);

    // Searching for ^Nt.*
    let nt_functions: Vec<&Export> =
        exported_functions
        .iter()
        .filter(|&x| {
            x.name.starts_with("Nt")
        }).collect();

    println!("[^-^] {:#?}", nt_functions);
}

fn example_get_function_address(module_name: &str, function_name: &str) {
    let module_address = unsafe { get_module_address(module_name) }.unwrap_or_else(|err| {
        eprintln!("[TwT] {:#?}", err);
        std::process::exit(1)
    });
    println!("[^-^] Module {:?} found at address : {:?}", module_name, module_address);
    println!("[^-^] Looking for function {:#x?}", function_name);

    let result = unsafe { get_function_address(function_name, module_address) };
    match result {
        Ok(function_address) => println!("[^o^] Function address: {:?}", function_address),
        Err(error) => eprintln!("[TwT] {:?}", error),
    }
}


fn test_syscall() {
    let ssn_array = unsafe{
        thermite::syscalls::search(|&x| {
           x.name.starts_with("Nt")
        }, simple_get_ssn)
    }.unwrap();

    println!("[^-^] Done! I found {:#?} matching syscalls !", ssn_array.len());
    if ssn_array.len() < 20 {
        println!("{ssn_array:#x?}");
    }



    // let mut unique_addr: Vec<*const u8> = ssn_array.iter().map(|x| {
    //     x.address
    // }).collect();
    // unique_addr.sort();
    // unique_addr.dedup();
    //
    // println!("[^-^] {:#?} addresses are unique", unique_addr.len());


}