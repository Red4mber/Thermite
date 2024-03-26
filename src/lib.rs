#![feature(pointer_byte_offsets)] // I should find a way to do without


use std::ffi::CStr;
use std::arch::asm;
use std::slice;

mod types;

use types::peb_teb::{PEB, LDR_DATA_TABLE_ENTRY};
use types::pe_file_format::{IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS};
use crate::types::pe_file_format::IMAGE_NT_SIGNATURE;


/// An error that can occur when trying to get the base address of a module.
#[derive(Debug)]
pub enum GetModuleAddressError {
    /// The requested module was not found.
    ModuleNotFound,
    /// An error occurred while retrieving the Process Environment Block (PEB).
    PebError,
    /// An error occurred while accessing the Loader Data or module list.
    LoaderDataError,
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
/// use thermite::get_module_address;
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
    fn peb_pointer() -> *const u8 {
        #[cfg(target_arch = "x86")]
        unsafe {
            let peb: *const u8;
            asm!("mov eax, fs:[0x30]", out("eax") peb, options(nomem, nostack, preserves_flags));
            peb
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let peb: *const u8;
            asm!("mov rax, gs:[0x60]", out("rax") peb, options(nomem, nostack, preserves_flags));
            peb
        }
    }

    let peb_pointer = peb_pointer();
    if peb_pointer.is_null() {
        None
    } else {
        Some(&*(peb_pointer as *const PEB))
    }
}


/// An error that can occur when trying to get the address of a function.
#[derive(Debug)]
pub enum GetFunctionAddressError {
    /// The requested function was not found.
    FunctionNotFound,
    /// An error occurred while parsing the name of the function.
    FunctionNameParsingError,
    /// An error occurred while parsing the PE headers or export directory.
    PEParsingError,
}

//noinspection ALL
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
/// use thermite::get_function_address;
/// let module_base_address = /* ... */;
/// let function_name = "MyFunction";
/// let result = unsafe { get_function_address(function_name, module_base_address) };
/// match result {
///     Ok(function_address) => println!("Function address: {:?}", function_address),
///     Err(error) => println!("Error: {:?}", error),
/// }
/// ```
pub unsafe fn get_function_address(
    function_name: &str,
    base_address: *const u8,
) -> Result<*const u8, GetFunctionAddressError> {
    // Get the offset to the NT headers from the PE header
    let nt_offset = base_address.byte_offset(0x03c);

    // Get a reference to the NT headers and checks the signature
    let nt_header: &IMAGE_NT_HEADERS = &(base_address.byte_offset(*nt_offset as isize).cast::<IMAGE_NT_HEADERS>()).read();
    if nt_header.Signature != IMAGE_NT_SIGNATURE {
        return Err(GetFunctionAddressError::PEParsingError);
    }
    // Get a reference to the export directory
    let export_dir: &IMAGE_EXPORT_DIRECTORY = &(base_address.offset(
            nt_header.OptionalHeader.DataDirectory[0].VirtualAddress as isize
        ).cast::<IMAGE_EXPORT_DIRECTORY>()).read();


    let address_of_functions: &[u32] = slice::from_raw_parts(
        (base_address.byte_offset(export_dir.AddressOfFunctions as isize)).cast::<u32>(),
        export_dir.NumberOfFunctions as usize,
    );
    let address_of_name_ordinals: &[u16] = slice::from_raw_parts(
        (base_address.byte_offset(export_dir.AddressOfNameOrdinals as isize)).cast::<u16>(),
        export_dir.NumberOfNames as usize,
    );
    let address_of_names: &[u32] = slice::from_raw_parts(
        (base_address.byte_offset(export_dir.AddressOfNames as isize)).cast::<u32>(),
        export_dir.NumberOfNames as usize,
    );
    for (i, name_addr) in address_of_names.iter().enumerate() {
        match CStr::from_ptr((base_address as usize + *name_addr as usize) as *const i8).to_str() {
            Ok(s) => {
                if s.eq_ignore_ascii_case(function_name) {
                    let rva = address_of_functions[address_of_name_ordinals[i] as usize];
                    let true_address = (base_address as usize + rva as usize) as *const u8;
                    return Ok(true_address);
                }
            },
            Err(_) => {
                return Err(GetFunctionAddressError::FunctionNameParsingError);
            }
        };
    }
    Err(GetFunctionAddressError::FunctionNotFound)
}
