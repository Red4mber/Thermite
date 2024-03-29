
use crate::model::windows::peb_teb::PEB;
use std::arch::asm;

pub mod peb_walk;
pub mod error;
pub mod model;

pub mod syscalls;
