
pub mod error;
pub mod models;
pub mod peb_walk;

pub mod syscalls;

// Needed because macros are broken
extern crate self as thermite;



//
// Below are my own macros for debugging/logging
//

// Prints stuff, offset by one tab, to stay aligned with the nice headers
#[macro_export]
macro_rules! _debug_print {
    ($val:literal$(,)?) => {
        println!("\t{}", $val);
    };
    ($val:expr$(,)?) => {
        println!(
            "\t{} = {}",
            stringify!($val),
            format!("{:#x?}", $val)
                .replace("\n ", "\n\t-")
                .replace(['{', '}', '[', ']', ','], "")  // Also removing some clutter
                .trim()
        );
    };
}

#[macro_export] macro_rules! debug {
    () => {
        println!("[?-?] - [{}:{}:{}]", file!(), line!(), column!());
    };
    ($($val:expr$(,)?)*) => {
        println!("[?-?] - [{}:{}:{}]", file!(), line!(), column!());
        $({$crate::_debug_print!($val)})*;
    };
}

#[macro_export] macro_rules! info {
    // When just a string, simply print it
    ($lit:literal) => {
        println!("[^-^] {}", $lit);
    };
    ($arg:expr) => {
        println!("[^-^] {} => {}", stringify!($arg), $arg);
    };
    ($($arg:tt)*) => {
        println!("[^-^] {}", format!($($arg)*));
    };
}

#[macro_export] macro_rules! error {
    ($arg:literal) => {
        println!("[TwT] [{}:{}:{}] \n\t => {}", file!(), line!(), column!(), $arg);
    };
    ($arg:expr) => {
        println!("[TwT] [{}:{}:{}] \n\t => {} => {}", file!(), line!(), column!(), stringify!($arg), $arg);
    };
    ($($arg:tt)*) => {
        eprintln!("[TwT] [{}:{}:{}] \n\t => {}", file!(), line!(), column!(), format!($($arg)*));
    };
}

// Some cool stuff to maybe check out later:
//https://github.com/eliasjonsson023/inline_colorization/blob/master/src/lib.rs
//https://veykril.github.io/tlborm/decl-macros/patterns/tt-muncher.html