pub mod windows;


/// Represents a syscall, we mostly only need the name and System Service Number
/// Each [Syscall] struct contains the following fields:
///
/// * `name` - The name of the corresponding function function in Ntdll (`String`).
/// * `address` - The address of the corresponding function in Ntdll (`*const u8`).
/// * `ssn` - The ID of the syscall (`u16`).
#[derive(Debug, Clone)]
pub struct Syscall {
	pub name: String,
	pub address: *const u8,
	pub ssn: u16,
}

/// Represents a function in the export table of a DLL
/// Each [Export] struct contains the following fields:
///
/// * `name` - The name of the exported function (`String`).
/// * `address` - The address of the exported function (`*const u8`).
/// * `ordinal` - The ordinal number of the exported function (`u16`).
#[derive(Debug, Clone)]
pub struct Export {
	pub name: String,
	pub address: *const u8,
	pub ordinal: u16,
}


/// Represents a loaded DLL
#[derive(Debug, Clone)]
pub struct Module {
	pub name: String,
	pub address: *const u8,
}
