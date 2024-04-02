
pub mod error;
pub mod models;
pub mod peb_walk;

pub mod syscalls;

// Needed because macros are broken
extern crate self as thermite;


// Prints stuff, offset by one tab, to stay aligned with the nice headers
#[macro_export]
macro_rules! _debug_print {
    ($val:literal$(,)?) => {
        eprintln!("\t{}", $val);
    };
    ($val:expr$(;)+) => {
        eprintln!(
            "\t{} = {}",
            stringify!($val),
            format!("{:#x?}", $val)
                .replace("\n ", "\n\t-")
                .replace(['{', '}', '[', ']'], "")
                .trim()
        );
    };
    ($val:expr$(,)?) => {
        eprintln!(
            "\t{} = {}",
            stringify!($val),
            format!("{:#?}", $val)
                .replace("\n ", "\n\t-")
                .replace(['{', '}', '[', ']'], "")  // Also removing some clutter
                .trim()
        );
    };
}



#[macro_export] macro_rules! debug {
    ($($val:expr$(;)+)*) => {
        eprintln!("[?-?] - [{}:{}:{}]", file!(), line!(), column!());
        $({$crate::_debug_print!($val;)})*;
    };
    ($($val:expr$(,)?)*) => {
        eprintln!("[?-?] - [{}:{}:{}]", file!(), line!(), column!());
        $({$crate::_debug_print!($val)})*;
    };
}

// Counter for the Trace header
thread_local! {
    static COUNTER: std::cell::Cell<usize> = std::cell::Cell::new(0);
}
#[macro_export] macro_rules! info {
    // When no arguments, just trace
    () => {
         let count = COUNTER.with(|c| {
            let value = c.get();
            c.set(value + 1);
            value
        });
        println!("['u'] -> #{} - ln.{}", count,  line!());
    };
    // When just a string, simply print it
    ($lit:literal) => {
        println!("[^-^] {}", $lit);
    };
    ($exp:expr) => {
        println!("[^-^] {}", $exp);
    };
}

#[macro_export] macro_rules! error {
    ($err:expr) => {
        eprintln!("[X-X] [{}:{}:{}] \n\t => {}", file!(), line!(), column!(), $err);
    };
}

// Some cool stuff maybe for lateer:
//https://github.com/eliasjonsson023/inline_colorization/blob/master/src/lib.rs
//https://veykril.github.io/tlborm/decl-macros/patterns/tt-muncher.html