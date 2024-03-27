///////////////////////////////////////////////////////////
//
//        == DLL Export Table Parsing Functions ==
//          -- For Thermite: Offensive Rust --
//
//    Does all kinds of stuff, but mostly just to recover
//            Functions exported by DLLs
//
//          Made by RedAmber - 27 March 2024
///////////////////////////////////////////////////////////


use std::collections::HashMap;
use std::ffi::CStr;
use std::slice;

use crate::model::peb_teb::LDR_DATA_TABLE_ENTRY;
use crate::model::pe_file_format::{IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE};
use crate::error::{GetModuleAddressError, GetFunctionAddressError};
use crate::get_peb_address;


/// Structure in which we will store a function found in the export table
/// Will eventually move in it's own file, but it's not needed yet
#[derive(Debug, Clone)]
pub struct ExportedFunction {
    pub name: String,
    pub address: *const u8,
    pub ordinal: u16,
}



/// Gets the base address of a loaded module by its name.
///
/// # Arguments
///
/// * `module_name` - The name of the module to find the base address for.
///
/// # Returns
///
/// If the module is found, returns `Ok` with the base address as a raw pointer.
/// If the module is not found or an error occurs, returns `Err` with a custom error type.
///
/// # Safety
///
/// This function performs unsafe operations and assumes the presence and validity of various
/// Windows structures and memory layouts. It should only be called in a context where these
/// assumptions are valid.
///
/// # Example
/// ```
/// use thermite::exports::get_module_address;
/// let module_name = "kernel32.dll";
/// let result = unsafe { get_module_address(module_name) };
/// match result {
///     Ok(base_address) => println!("[^-^] Module base address: {:?}", base_address),
///     Err(error) => eprintln!("[TwT] Error: {:?}", error),
/// }
/// ```
pub unsafe fn get_module_address(module_name: &str) -> Result<*const u8, GetModuleAddressError> {
    // Get the address of the Process Environment Block (PEB)
    let peb = get_peb_address().ok_or(GetModuleAddressError::PebError)?;

    // Get a reference to the PEB 's Loader Data
    let ldr = (*peb).Ldr;

    // Get a reference to the InMemoryOrderModuleList's head and tail
    let mut list_entry = (*ldr).InMemoryOrderModuleList.Flink;
    let last_module = (*ldr).InMemoryOrderModuleList.Blink;

    loop {
        // If we've reached the end of the list, the module was not found
        if list_entry == last_module {
            return Err(GetModuleAddressError::ModuleNotFound);
        }

        // Get a reference to the current module's LDR_DATA_TABLE_ENTRY
        let module_base: *const LDR_DATA_TABLE_ENTRY =
            list_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;

        // Get the module's base name as a unicode string (defined in types::peb_teb.rs)
        let base_dll_name = (*module_base).BaseDllName.to_string();

        // If the base name matches the requested module name (case-insensitive)
        if base_dll_name.eq_ignore_ascii_case(module_name) {
            // Get the module's base address and return it
            let module_base_address = (*module_base).DllBase;
            return Ok(module_base_address as *const u8);
        }

        // Move to the next module in the list
        list_entry = (*list_entry).Flink;
    }
}




/// Parses the export directory of a PE (Portable Executable) file.
///
/// This function takes a raw pointer to the base address of the loaded PE file and parses
/// the export directory to retrieve the `IMAGE_EXPORT_DIRECTORY` structure and the associated
/// arrays containing information about the exported functions.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and relies on the correct
/// structure of the PE file. It is the caller's responsibility to ensure that the provided
/// base address points to a valid, loaded PE file.
///
/// # Arguments
///
/// * `base_address` - A raw pointer to the base address of the loaded PE file.
///
/// # Returns
///
/// A `Result` containing a tuple with the following elements:
///
/// * `&IMAGE_EXPORT_DIRECTORY` - A reference to the `IMAGE_EXPORT_DIRECTORY` structure.
/// * `&[u32]` - A slice containing the virtual addresses of the exported functions.
/// * `&[u16]` - A slice containing the ordinal numbers of the exported functions with names.
/// * `&[u32]` - A slice containing the virtual addresses of the exported function names.
///
/// If the PE file is invalid or an error occurs during parsing, the function returns an
/// appropriate `GetFunctionAddressError`.
///
/// # Examples
///
/// ```
///  use std::ptr;
///
///
///  fn main() {
///      use thermite::exports::parse_export_directory;
///      let base_address: *const u8 = ptr::null();
///      unsafe {
///          let (export_dir, address_of_functions, address_of_name_ordinals, address_of_names) =
///              parse_export_directory(base_address).unwrap();
///          // Use the parsed export directory information
///      }
///  }
/// ```
pub unsafe fn parse_export_directory<'a>(
    base_address: *const u8,
) -> Result<(IMAGE_EXPORT_DIRECTORY, &'static[u32], &'static[u16], &'static[u32]), GetFunctionAddressError> {
    // Get the offset to the NT headers from the PE header
    let nt_offset = base_address.byte_offset(0x03c);

    // Get a reference to the NT headers and check the signature
    let nt_header: &IMAGE_NT_HEADERS = &base_address.byte_offset(*nt_offset as isize).cast::<IMAGE_NT_HEADERS>().read();
    if nt_header.Signature != IMAGE_NT_SIGNATURE {
        return Err(GetFunctionAddressError::PEParsingError);
    }

    // Get a reference to the export directory
    let export_dir: IMAGE_EXPORT_DIRECTORY = base_address.offset(
        nt_header.OptionalHeader.DataDirectory[0].VirtualAddress as isize
    ).cast::<IMAGE_EXPORT_DIRECTORY>().read();

    let address_of_functions: &[u32] = slice::from_raw_parts(
        base_address.byte_offset(export_dir.AddressOfFunctions as isize).cast::<u32>(),
        export_dir.NumberOfFunctions as usize,
    );
    let address_of_name_ordinals: &[u16] = slice::from_raw_parts(
        base_address.byte_offset(export_dir.AddressOfNameOrdinals as isize).cast::<u16>(),
        export_dir.NumberOfNames as usize,
    );
    let address_of_names: &[u32] = slice::from_raw_parts(
        base_address.byte_offset(export_dir.AddressOfNames as isize).cast::<u32>(),
        export_dir.NumberOfNames as usize,
    );

    Ok((export_dir, address_of_functions, address_of_name_ordinals, address_of_names))
}


/// Retrieves a mapping of all exported functions from a PE (Portable Executable) file.
///
/// This function takes a raw pointer to the base address of the loaded PE file and parses
/// the export directory to retrieve information about all exported functions. The resulting
/// mapping associates each function's ordinal number with a struct containing the function's
/// name, address, and ordinal number.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and relies on the correct
/// structure of the PE file. It is the caller's responsibility to ensure that the provided
/// base address points to a valid, loaded PE file.
///
/// # Arguments
///
/// * `base_address` - A raw pointer to the base address of the loaded PE file.
///
/// # Returns
///
/// A `Result` containing a `HashMap` that maps ordinal numbers (`u16`) to `ExportedFunction`
/// structs. Each `ExportedFunction` struct contains the following fields:
///
/// * `name` - The name of the exported function (`String`).
/// * `address` - The address of the exported function (`*const u8`).
/// * `ordinal` - The ordinal number of the exported function (`u16`).
///
/// If the PE file is invalid or an error occurs during parsing, the function returns an
/// appropriate `GetFunctionAddressError`.
///
/// # Examples
///
/// ```
///  use std::collections::HashMap;
///  use std::ptr;
///
///  fn main() {
///      let module_address = unsafe { thermite::exports::get_module_address("ntdll.dll") }.unwrap_or_else(|err| {
///          eprintln!("[TwT] {:#?}", err);
///          std::process::exit(1)
///      });
///      unsafe {
///          let exported_functions = thermite::exports::get_all_exported_functions(module_address).unwrap();
///          // Use the exported functions mapping
///      }
///  }
/// ```
pub unsafe fn get_all_exported_functions(
    base_address: *const u8,
) -> Result<HashMap<u16, ExportedFunction>, GetFunctionAddressError> {
    let (_, address_of_functions, address_of_name_ordinals, address_of_names) =
        parse_export_directory(base_address)?;

    let mut exported_functions = HashMap::new();

    // We iterate over the list of names
    for (i, name_addr) in address_of_names.iter().enumerate() {


        // Then match over the result of CStr::from_ptr to capture eventual errors
        match CStr::from_ptr((base_address as usize + *name_addr as usize) as *const i8).to_str() {
            Ok(function_name) => {
                // Get the address of the function
                let rva = address_of_functions[address_of_name_ordinals[i] as usize];
                let true_address = (base_address as usize + rva as usize) as *const u8;
                // Add the function to the HashMap
                exported_functions.insert(
                    address_of_name_ordinals[i],
                    ExportedFunction {
                        name: function_name.to_owned(),
                        address: true_address,
                        ordinal: address_of_name_ordinals[i],
                    }
                );
            },
            Err(e) => {
                return Err(GetFunctionAddressError::FunctionNameParsingError(e));
            }
        };
    }
    Ok(exported_functions)
}



/// Gets the address of a function by its name in a loaded module.
///
/// # Arguments
///
/// * `function_name` - The name of the function to find the address for.
/// * `base_address` - The base address of the module containing the function.
///
/// # Returns
///
/// If the function is found, returns `Ok` with the function address as a raw pointer.
/// If the function is not found or an error occurs, returns `Err` with a custom error type.
///
/// # Safety
///
/// This function performs unsafe operations and assumes the presence and validity of various
/// Windows structures and memory layouts. It should only be called in a context where these
/// assumptions are valid.
///
/// # Example
///
/// ```
///  use thermite::exports::get_function_address;
///  let module_name = "ntdll.dll";
///  let function_name = "NtOpenProcess";
///  let module_address = unsafe { thermite::exports::get_module_address(module_name) }.unwrap_or_else(|err| {
///          eprintln!("[TwT] {:#?}", err);
///          std::process::exit(1)
///      });
///      println!("[^-^] Module {:?} found at address : {:?}", module_name, module_address);
///      println!("[^-^] Looking for function {:#x?}", function_name);
///
///      let result = unsafe { get_function_address(function_name, module_address) };
///      match result {
///          Ok(function_address) => println!("[^o^] Function address: {:?}", function_address),
///          Err(error) => eprintln!("[TwT] {:?}", error),
///      }
/// ```
pub unsafe fn get_function_address(
    function_name: &str,
    base_address: *const u8,
) -> Result<*const u8, GetFunctionAddressError> {

    let (_, address_of_functions, address_of_name_ordinals, address_of_names) =
        parse_export_directory(base_address)?;

    // We're searching by name so we iterate over the list of names
    for (i, name_addr) in address_of_names.iter().enumerate() {
        // Then match over the result of CStr::from_ptr to capture eventual errors
        match CStr::from_ptr((base_address as usize + *name_addr as usize) as *const i8).to_str() {
            Ok(s) => {
                // If it's ok, we test if our strings match
                if s.eq_ignore_ascii_case(function_name) {
                    // if it does, we return the address of the function
                    let rva = address_of_functions[address_of_name_ordinals[i] as usize];
                    let true_address = (base_address as usize + rva as usize) as *const u8;
                    return Ok(true_address);
                }
            },
            // If we captured an error, we return it to the caller via our own error type
            Err(e) => {
                return Err(GetFunctionAddressError::FunctionNameParsingError(e));
            }
        };
    }
    Err(GetFunctionAddressError::FunctionNotFound)
}


