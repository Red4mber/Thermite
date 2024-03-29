pub mod windows;





// SYSCALL MODELS
// ---

/// Structure in which we will store a syscall with only the data we really need
#[derive(Debug, Clone)]
pub struct Syscall {
    pub name: String,
    pub address: *const u8,
    pub ssn: u16,
}

// PEB WALK MODELS
// ---

/// Structure in which we will store a function found in the export table
#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub address: *const u8,
    pub ordinal: u16,
}

/// Structure in which we will store a module's information
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub address: *const u8,
}
