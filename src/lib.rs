pub mod error;
pub mod models;
pub mod peb_walk;

pub mod syscalls;

// Needed because macros are broken
extern crate self as thermite;

#[macro_export]
macro_rules! debug {
    () => { eprintln!("[?-?] - [{}:{}:{}]", file!(), line!(), column!()); };
    ($($val:expr$(,)?)*) => {
        $crate::debug!();
        $({$crate::_debug_print!($val)})*;
    };
}
#[macro_export]
macro_rules! _debug_print {
    ($val:literal$(,)?) => {
        eprintln!("\t{}", $val);
    };
    ($val:expr$(,)?) => {
        eprintln!(
            "\t{} = {}",
            stringify!($val),
            format!("{:#x?}", $val)
                .replace("\n ", "\n\t-")
                .replace(['{', '}'], "")
                .trim()
        );
    };
}
