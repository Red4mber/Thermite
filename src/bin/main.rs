#![allow(unused)]

use thermite::error::DllParserError;
use thermite::models::Export;
use thermite::peb_walk::{
    get_all_exported_functions, get_function_address, get_module_address, list_modules,
};
use thermite::syscalls::simple_get_ssn;
use thermite::{count_args, syscall, syscalls};

// This file mostly serve as a scratchpad to test stuff
// none of what's here is really made to be definitive or representative of anything
// Go check out the [examples/] folder for real examples

fn main() {}

// Below are testing / example functions
// I will move them eventually, but I'm still working on it
fn examples_all_exports() {
    // Get the address of a DLL
    let module_address = unsafe { get_module_address("ntdll.dll") }.unwrap_or_else(|err| {
        eprintln!("[TwT] {:#?}", err);
        std::process::exit(1)
    });

    // Parse the export table
    let mut exported_functions: Vec<Export> = unsafe { get_all_exported_functions(module_address) }
        .unwrap_or_else(|err: DllParserError| {
            eprintln!("[TwT] {:#?}", err);
            std::process::exit(1)
        });

    // Sort alphabetically by function name
    exported_functions.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    // Sort by address name
    exported_functions.sort_by(|a, b| a.address.cmp(&b.address));

    println!("[^-^] {:#?}", exported_functions);

    // Searching for ^Nt.*
    let nt_functions: Vec<&Export> = exported_functions
        .iter()
        .filter(|&x| x.name.starts_with("Nt"))
        .collect();

    println!("[^-^] {:#?}", nt_functions);
}

fn example_get_function_address(module_name: &str, function_name: &str) {
    let module_address = unsafe { get_module_address(module_name) }.unwrap_or_else(|err| {
        eprintln!("[TwT] {:#?}", err);
        std::process::exit(1)
    });
    println!(
        "[^-^] Module {:?} found at address : {:?}",
        module_name, module_address
    );
    println!("[^-^] Looking for function {:#x?}", function_name);

    let result = unsafe { get_function_address(function_name, module_address) };
    match result {
        Ok(function_address) => println!("[^o^] Function address: {:?}", function_address),
        Err(error) => eprintln!("[TwT] {:?}", error),
    }
}

fn no_filter(x: &&Export) -> bool {
    true
}

fn miscellanous_examples() {
    // Get a list of all exports
    let module_address = unsafe { get_module_address("ntdll.dll") }.unwrap();
    let all_exports = unsafe { get_all_exported_functions(module_address) }.unwrap();

    // Get a list of all syscalls
    let all_syscalls = syscalls::search(
        |x| true,       // Do no filter exports
        simple_get_ssn, // Just search for SSNs to get all syscalls
    )
    .unwrap();
    println!(
        "[^-^] I found {:#?} syscalls in {:#?} exports",
        all_syscalls.len(),
        all_exports.len()
    );
}
