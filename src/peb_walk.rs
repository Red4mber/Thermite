//!
//! Module containing all functions related to PEB Walking and DLL parsing :
//!
/// Functions in this module:
/// [get_peb_address], [get_module_handle], [list_all_loaded_modules], [parse_export_directory],
/// [get_all_exported_functions], [get_function_address]

use std::arch::asm;
use std::ffi::CStr;
use std::slice;

use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::{PEB, TEB};
use winapi::shared::minwindef::HMODULE;
use winapi::um::winnt::{IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE};

use crate::error::DllParserError;
use crate::utils::handle_unicode_string;


/// Represents a loaded DLL
#[derive(Debug, Clone)]
pub struct Module {
	pub name: String,
	pub address: *const u8,
}


/// Represents a function in the export table of a DLL
/// Each [ExportedFunction] struct contains the following fields:
///
/// * `name` - The name of the exported function (`String`).
/// * `address` - The address of the exported function (`*const u8`).
/// * `ordinal` - The ordinal number of the exported function (`u16`).
#[derive(Debug, Clone)]
pub struct ExportedFunction {
	pub name: String,
	pub address: *const u8,
	pub ordinal: u16,
}

/// This function uses inline assembly to retrieve the TEB address.
///
/// ## Returns
/// Returns a pointer to the TEB.
///
/// ## Safety
/// This function is unsafe because it executes inline assembly to read from a register.
///
/// ## Notes
/// Only supports x86 or x86_64
///
pub fn get_teb_address() -> *const TEB {
	#[cfg(target_arch = "x86")]
	unsafe {
		let teb: *const TEB;
		asm!("mov eax, fs:[0x30]", out("eax") teb, options(nomem, nostack, preserves_flags));
		teb
	}
	#[cfg(target_arch = "x86_64")]
	unsafe {
		let teb: *const TEB;
		asm!("mov rax, gs:[0x30]", out("rax") teb, options(nomem, nostack, preserves_flags));
		teb
	}
}

/// This function uses inline assembly to retrieve the PEB address from the appropriate
/// Thread environment Block (TEB) field based on the target architecture .
///
/// ## Returns
/// Returns a pointer to the PEB.
///
pub fn get_peb_address() -> *const PEB {
	let teb = get_teb_address();
	unsafe { (*teb).ProcessEnvironmentBlock } 
}


/// Returns the address of a loaded DLL
///
/// ## Arguments
/// * `module_name` - The name of the module to find the base address for.
///
/// ## Returns
/// If the module is found, returns `Ok` with the base address as a raw pointer.
/// If the module is not found or an error occurs, returns `Err` with a [DllParserError].
///
/// ## Safety
/// This function is unsafe because it dereferences raw pointers and relies on the correct structure of the Process Environment Block.
///
/// ## Example
/// ```
/// let module_name = "kernel32.dll";
/// match unsafe { thermite::peb_walk::get_module_handle(module_name) } {
///     Ok(base_address) => println!("[^-^] Module base address: {:?}", base_address),
///     Err(error) => eprintln!("[TwT] Error: {:?}", error),
/// };
/// ```
pub unsafe fn get_module_handle(module_name: &str) -> Result<HMODULE, DllParserError> {
	// Get the address of the Process environment Block (PEB)
	let peb = get_peb_address();

	// Get a reference to the PEB 's Loader Data
	let ldr = (*peb).Ldr;

	// Get a reference to the list's head and tail
	let mut list_entry = (*ldr).InMemoryOrderModuleList.Flink;
	let last_module = (*ldr).InMemoryOrderModuleList.Blink;

	loop {
		// If we've reached the end of the list, the module was not found
		if list_entry == last_module {
			return Err(DllParserError::ModuleNotFound);
		}

		// Get a reference to the current module's LDR_DATA_TABLE_ENTRY
		let module_base = list_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;
		
		let base_dll_name = handle_unicode_string((*module_base).BaseDllName);
		
		// If the base name matches the requested module name (case-insensitive)
		if base_dll_name.eq_ignore_ascii_case(module_name) {
			// Get the module's base address and return it
			let module_base_address = (*module_base).DllBase;
			return Ok(module_base_address as _);
		}

		// Move to the next module in the list
		list_entry = (*list_entry).Flink;
	}
}


/// Retrieves a list of all modules loaded in memory.
///
/// This function will walk the PEB and other related memory structures
///
/// # Returns
/// A `Result` containing a `Vector` that contains [`Module`] structs.
///
/// Each `Module` struct contains the following fields:
/// - `name` - The name of the exported function (`String`).
/// - `address` - The address of the loaded DLL (`*const u8`).
/// If the function fails to read the Process environment Block, the function returns a
/// `GetModuleAddressError::PebError`.
/// ## Safety
/// This function is unsafe because it dereferences raw pointers and relies on the correct structure of the Process Environment Block.
/// # Examples
/// ```
/// let all_modules = unsafe { thermite::peb_walk::list_all_loaded_modules() }.unwrap();
/// println!("[^-^] Loaded Modules : {:#?}", all_modules);
/// ```
pub unsafe fn list_all_loaded_modules() -> Result<Vec<Module>, DllParserError> {
	let loader_info = (*get_peb_address()).Ldr;
	let mut list_entry = (*loader_info).InMemoryOrderModuleList.Flink;
	let last_module = (*loader_info).InMemoryOrderModuleList.Blink;
	let mut loaded_modules: Vec<Module> = vec![];
	loop {
		let module_base = list_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;
		
		loaded_modules.push(Module {
			name: handle_unicode_string((*module_base).BaseDllName),
			address: (*module_base).DllBase as *const u8,
		});

		if list_entry == last_module {
			return Ok(loaded_modules);
		}
		list_entry = (*list_entry).Flink;
	}
}


/// Represents the contents of the export directory of a DLL
type ExportsDir<'a> = (IMAGE_EXPORT_DIRECTORY, &'a [u32], &'a [u16], &'a [u32]);


/// Returns the [ImageExportDirectory] of loaded DLL and the `address_of_functions`, `address_of_name_ordinals` and `address_of_names` arrays referenced inside
///
/// Mostly just made to avoid having to repeat this code in every function that need them
unsafe fn parse_export_directory<'a>(
	module_handle: HMODULE
) -> Result<ExportsDir<'a>, DllParserError> {
	let base_address = module_handle as *const u8;
	// Get the offset to the NT headers from the PE header
	let nt_offset = base_address.byte_offset(0x03c);

	// Get a reference to the NT headers and check the signature
	let nt_header: &IMAGE_NT_HEADERS = &base_address
		.byte_offset(*nt_offset as isize)
		.cast::<IMAGE_NT_HEADERS>()
		.read();
	if nt_header.Signature != IMAGE_NT_SIGNATURE {
		return Err(DllParserError::InvalidNtHeader);
	}

	// Get a reference to the export directory
	let export_dir: IMAGE_EXPORT_DIRECTORY = base_address
		.offset(nt_header.OptionalHeader.DataDirectory[0].VirtualAddress as isize)
		.cast::<IMAGE_EXPORT_DIRECTORY>()
		.read();

	let address_of_functions: &[u32] = slice::from_raw_parts(
		base_address
			.byte_offset(export_dir.AddressOfFunctions as isize)
			.cast::<u32>(),
		export_dir.NumberOfFunctions as usize,
	);
	let address_of_name_ordinals: &[u16] = slice::from_raw_parts(
		base_address
			.byte_offset(export_dir.AddressOfNameOrdinals as isize)
			.cast::<u16>(),
		export_dir.NumberOfNames as usize,
	);
	let address_of_names: &[u32] = slice::from_raw_parts(
		base_address
			.byte_offset(export_dir.AddressOfNames as isize)
			.cast::<u32>(),
		export_dir.NumberOfNames as usize,
	);

	Ok((
		export_dir,
		address_of_functions,
		address_of_name_ordinals,
		address_of_names,
	))
}


/// Finds the address of a function by its name in the export table of a loaded module.
///
/// # Arguments
/// * `function_name` - The name of the function to find the address for.
/// * `base_address` - The base address of the module containing the function.
///
/// # Returns
/// If the function is found, returns `Ok` with a raw pointer (`*const u8`) to the function.
/// If the function is not found or an error occurs, returns `Err` with a custom error type.
///
/// ## Safety
/// This function is unsafe because it dereferences raw pointers and relies on the correct structure of the DLL.
///
/// # Example
/// ```
/// let module_address = unsafe { thermite::peb_walk::get_module_handle("ntdll.dll") }.unwrap();
///
/// let result = unsafe {
///     thermite::peb_walk::get_function_address("NtOpenProcess", module_address)
/// };
/// match result {
///     Ok(function_address) => println!("[^-^] Function address: {:?}", function_address),
///     Err(err) => eprintln!("[TwT] {:?}", err),
/// }
/// ```
pub unsafe fn get_function_address(
	function_name: &str,
	module_handle: HMODULE
) -> Result<*const u8, DllParserError> {
	let (_, address_of_functions, address_of_name_ordinals, address_of_names) =
		parse_export_directory(module_handle)?;

	// We're searching by name, so we iterate over the list of names
	for (i, name_addr) in address_of_names.iter().enumerate() {
		// Then match over the result of CStr::from_ptr to capture eventual errors
		match CStr::from_ptr((module_handle as usize + *name_addr as usize) as *const i8).to_str() {
			Ok(s) => {
				// If it's ok, we test if our strings match
				if s.eq_ignore_ascii_case(function_name) {
					// if it does, we return the address of the function
					let rva = address_of_functions[address_of_name_ordinals[i] as usize];
					let true_address = (module_handle as usize + rva as usize) as *const u8;
					return Ok(true_address);
				}
			}
			// If we captured an error, we forward it to the caller with our own error type
			Err(e) => {
				return Err(DllParserError::FunctionNameParsingError(e));
			}
		};
	}
	Err(DllParserError::FunctionNotFound)
}


/// Retrieves a list of all exported functions from a loaded DLL.
///
/// This function takes a raw pointer to a loaded DLL and parses its export directory to retrieve all the exported functions.
/// The resulting vector contains structures, each containing the function's name, address, and ordinal number.
///
/// # Arguments
/// * `base_address` - A raw pointer to the base address of the loaded DLL.
///
/// # Returns
/// A `Result` containing a `Vec` that contains [ExportedFunction] structs.
///
/// If the DLL is invalid or an error occurs during parsing, the function returns an
/// appropriate [DllParserError].
///
/// ## Safety
/// This function is unsafe because it relies on the correct structure of the DLL it is parsing.
///
/// # Usage :
/// ```
/// use thermite::error::DllParserError;
/// use thermite::peb_walk::{ExportedFunction, get_all_exported_functions};
///
/// // Get the address of a loaded DLL
/// let module_address = unsafe { thermite::peb_walk::get_module_handle("ntdll.dll") }.unwrap();
/// // Retrieve vec of exported functions
/// let mut exported_functions: Vec<ExportedFunction> = unsafe { get_all_exported_functions(module_address) }.unwrap();
/// ```
pub unsafe fn get_all_exported_functions(
	module_handle: HMODULE
) -> Result<Vec<ExportedFunction>, DllParserError> {
	let (_, address_of_functions, address_of_name_ordinals, address_of_names) =
		parse_export_directory(module_handle)?;
	let mut exported_functions = Vec::new();
	// We iterate over the list of names
	for (i, name_addr) in address_of_names.iter().enumerate() {
		// Then match over the result of CStr::from_ptr to capture eventual errors
		match CStr::from_ptr((module_handle as usize + *name_addr as usize) as *const i8).to_str() {
			Ok(function_name) => {
				// Get the address of the function
				let rva = address_of_functions[address_of_name_ordinals[i] as usize];
				let true_address = (module_handle as usize + rva as usize) as *const u8;
				// Push the functions name and address to the return vector
				exported_functions.push(ExportedFunction {
					name: function_name.to_owned(),
					address: true_address,
					ordinal: address_of_name_ordinals[i],
				});
			}
			Err(e) => {
				return Err(DllParserError::FunctionNameParsingError(e));
			}
		};
	}
	Ok(exported_functions)
}
