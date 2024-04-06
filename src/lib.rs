// Needed because macros are broken
extern crate self as thermite;


pub mod error;
pub mod models;
pub mod peb_walk;
pub mod syscalls;
pub mod enumeration;
pub mod utils;


// Some cool stuff to maybe check out later:
//https://github.com/eliasjonsson023/inline_colorization/blob/master/src/lib.rs
//https://veykril.github.io/tlborm/decl-macros/patterns/tt-muncher.html