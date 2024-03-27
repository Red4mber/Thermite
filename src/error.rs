///////////////////////////////////////////////////////////
//
//             -- Thermite: Offensive Rust --
//                    ERRORS Module
//
//                  Nothing spectacular
//           just describes the various errors
//        you might face while using this library
//
//          Made by RedAmber - 27 March 2024
///////////////////////////////////////////////////////////
use std::str::Utf8Error;


/// An error that can occur when trying to get the address of a function.
#[derive(Debug)]
pub enum GetFunctionAddressError {
    /// The requested function was not found.
    FunctionNotFound,
    /// An error occurred while parsing the name of the function.
    FunctionNameParsingError(Utf8Error),
    /// An error occurred while parsing the PE headers or export directory.
    PEParsingError,
}

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
