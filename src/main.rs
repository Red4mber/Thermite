

use thermite::exports::{get_module_address, get_function_address, get_all_exported_functions};
use std::collections::HashMap;
use std::ptr;


fn main() {
    // test_get_function_address("ntdll.dll", "NtOpenProcess");

    // let all_exports = unsafe {
    //     get_all_exported_functions(
    //         get_module_address("ntdll.dll").expect("")
    //     ).expect("");
    // };
    // println!("[^-^] {:?}", all_exports);
    test_all_exports();
}

fn test_all_exports() {
    let module_address = unsafe { get_module_address("ntdll.dll") }.unwrap_or_else(|err| {
        eprintln!("[TwT] {:#?}", err);
        std::process::exit(1)
    });
    unsafe {
        let exported_functions = get_all_exported_functions(module_address).unwrap_or_else(|err| {
             eprintln!("[TwT] {:#?}", err);
             std::process::exit(1)
        });
        // You can now use the exported functions mapping
        println!("[^-^] {:#?}", exported_functions);
    }
}





fn test_get_function_address(module_name: &str, function_name: &str) {
    let module_address = unsafe { get_module_address(module_name) }.unwrap_or_else(|err| {
        eprintln!("[TwT] {:#?}", err);
        std::process::exit(1)
    });
    println!("[^-^] Module {:?} found at address : {:?}", module_name, module_address);
    println!("[^-^] Looking for function {:#x?}", function_name);

    // let address = get_function_address(function_name, module_address);
    let result = unsafe { get_function_address(function_name, module_address) };
    match result {
        Ok(function_address) => println!("[^o^] Function address: {:?}", function_address),
        Err(error) => eprintln!("[TwT] {:?}", error),
    }
}