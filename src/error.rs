use std::fmt;
use std::fmt::Formatter;
use std::str::Utf8Error;

/// Errors occurring during the parsing of DLLs
pub enum DllParserError {
    /// Failed to retrieve a pointer to the Process Environment Block (PEB).
    PebError,
    /// The requested function was not found.
    FunctionNotFound,
    /// An error occurred while parsing the name of the function.
    FunctionNameParsingError(Utf8Error),
    /// An error occurred while parsing the PE headers or export directory.
    InvalidNtHeader,
    /// The requested module was not found.
    ModuleNotFound,
}
impl fmt::Display for DllParserError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PebError => write!(f, "Invalid PEB pointer"),
            Self::FunctionNotFound => write!(f, "The requested function was not found"),
            Self::FunctionNameParsingError(err) => write!(f, "Failed to parse function name : {err}"),
            Self::InvalidNtHeader => write!(f, "Failed to parse module: Invalid NT Signature"),
            Self::ModuleNotFound => write!(f, "The requested module was not found"),
        }
    }
}
impl fmt::Debug for DllParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
pub enum SyscallError {
    /// The SSN could not be found
    SSNNotFound,
}
impl fmt::Display for SyscallError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SSNNotFound => write!(f, "The requested System Service Number was not found")
        }
    }
}
impl fmt::Debug for SyscallError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
pub enum ThermiteError {
    DllParserError(DllParserError),
    SyscallError(SyscallError),
}
impl fmt::Display for ThermiteError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DllParserError(err) => write!(f, "{}", err.to_string()),
            Self::SyscallError(err) => write!(f, "{}", err.to_string()),
        }
    }

}
impl fmt::Debug for ThermiteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}