pub mod windows;

/// Represents a syscall, we mostly only need the name and System Service Number
/// But keeping the address of syscalls allows us to sort them, to take a guess at SSNs we couldn't find
#[derive(Debug, Clone)]
pub struct Syscall {
    pub name: String,
    pub address: *const u8,
    pub ssn: u16,
}

/// Represents a function in the export table of a DLL
#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub address: *const u8,
    pub ordinal: u16,
}

/// Structure to represent a loaded DLL
/// We only really need the name and address
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub address: *const u8,
}
