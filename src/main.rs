

use thermite::{get_module_address, get_function_address};

fn main() {
    unsafe {
        let module_name = "ntdll.dll";
        let function_name = "NtOpenProcess";

        let module_address = get_module_address(module_name).unwrap_or_else(|err| {
            eprintln!("[TwT] {:#?}", err);
            std::process::exit(1)
        });
        println!("[^-^] Module {:?} found at address : {:?}", module_name, module_address);
        println!("[^-^] Looking for function {:#x?}", function_name);

        // let address = get_function_address(function_name, module_address);
        let result = get_function_address(function_name, module_address);
        match result {
            Ok(function_address) => println!("[^o^] Function address: {:?}", function_address),
            Err(error) => println!("[TwT] {:?}", error),
        }
    }
}

