use std::arch::global_asm;
use std::ptr;

use crate::error::DllParserError;
use crate::models::{Export, Syscall};
use crate::peb_walk::{get_all_exported_functions, get_function_address, get_module_address};

/*
Parameter 1, 2, 3, 4 in RCX, RDX, R8, and R9,
The fifth and higher arguments are called stack parameters, they will be pushed on the stack (starting at RSP+28)

Because we cannot dynamically generate the assembly code and execute it at runtime, we need to craft
a syscall stub that can take the SSN as argument which then causes all the other arguments to end up in the next register.
(with the SSN now being Arg1, Arg1 becomes Arg2, which in turn ends up as Arg3 etc...)
So we need to put them back in order before executing the syscall instruction.

However, there is a single exception to this calling convention, only for syscalls, the first parameter goes in the r10 register
this is because the syscall instruction will overwrite RCX eventually, so we move rcx to r10 to preserve it

The stack parameters are also a little bit more complicated than the first four parameters :
When we check if we have more than 4 parameters, we decrement RCX (which is arg. count) by 4, then jump if RCX < 0,
This has the added benefit of storing the number of stack parameters in RCX, because we now don't count the first four stored in registers
This has even a third benefit, when looping using the REP instruction, RCX gets decremented,
giving us a 3-for-1 combo = Comparison + Counter + Loop in a single register o//

It's quite a smart solution and I take absolutely zero credit for it, I found this on GitHub
I tried rewriting it myself but end up rewriting exactly the same stub each time :|
                ___go check janoglezcampos/syscall-rs on GitHub___
*/
global_asm!(
    r#"
.global syscall_handler
.section .text

syscall_handler:
    mov [rsp - 0x8],  rsi       // Backup the value of RSI to the stack
    mov [rsp - 0x10], rdi       // Backup the value of RDI to the stack

    mov eax, ecx                // Move the sycall number to RAX
    mov rcx, rdx                // Move the arguments number in RCX

    mov r10, r8                 // Move Arg1 in R10                         // syscall overwrite RCX so Arg1 goes to r10
    mov rdx, r9                 // Move Arg2 in RDX
    mov  r8,  [rsp + 0x28]      // Move Arg3 in R8
    mov  r9,  [rsp + 0x30]      // Move Arg4 in R9

    sub rcx, 0x4                // Substract 4 from RCX                     // Do we have stack params ?
    jle execute                 // If zero or less, skip to the end         // If yes

    lea rsi,  [rsp + 0x38]      // Move the address of [rsp + 0x38] in RSI
    lea rdi,  [rsp + 0x28]      // Move the address of [rsp + 0x28] in RDI

    rep movsq                   // Move qword from [RSI] to [RDI], repeat RCX times  // Move every stack parameter "down"
execute:
    syscall                     // Perform the Syscall

    mov rsi, [rsp - 0x8]        // Restore value of RSI
    mov rdi, [rsp - 0x10]       // Restore value of RDI
    ret                         // Return
"#
);

#[allow(unused)]
extern "C" {
    /// Our wrapper around syscall, imported from the assembly code above
    ///
    /// Not really made to be called directly, it is better to use the [`thermite::syscall`] macro.
    ///
    /// ### Arguments :
    ///  - `ssn` : 16-bit unsigned int, the System Service Number of the syscall you want to call
    ///  - `arg_count`: 32-bit unsigned int, refers to the count of arguments to pass to syscall (excluding these two, which are not passed to syscall)
    ///  - ...  -> Then, every argument to pass to the syscall instruction.
    pub fn syscall_handler(ssn: u16, arg_count: u32, ...) -> i32;
}

/// Very simple function that reads a SSN from a clean syscall stubs
///
/// # How?
/// Here's a "virgin" syscall stub, not hooked by an EDR:
/// ```n
/// Bytes : ________________  ;  Asm:_________
/// 0x4c 0x8b 0xd1            ;	 mov r10, rcx
/// 0xb8 0x?? 0x?? 0x00 0x00  ;	 mov eax, 0x?? 0x?? 0x00 0x00
/// ; <etc...>                ;  <etc...>
/// ```
/// So we know we can find the SSN in after the MOV EAX instruction, in the 5 and 6th bytes of the function
/// So if the 4 first bytes are `0x4c`, `0x8b`, `0xd1` and `0xb8`,
/// We know the fifth byte will be the SSN, and we can return it safely
///
/// If we don't find these bytes, it's either not a valid syscall address, either a valid syscall which has been modified, by
/// We cannot recover the SSN so we just return None
///
/// # Arguments
///
/// - `syscall_addr` : The address of the function we are looking for, can be obtained with [`get_function_address`]
///
pub fn simple_get_ssn(syscall_addr: *const u8) -> Option<u16> {
    unsafe {
        if ptr::read(syscall_addr as *const [u8; 4]) == [0x4c, 0x8b, 0xd1, 0xb8] {
            // The function is clean
            Some(ptr::read(syscall_addr.add(4)) as u16)
        } else {
            // The function is hooked, or modified in some way
            None
        }
    }
}

/// Searches for every syscalls using the provided pattern
/// It then executes the find_ssn function on every one of them to retrieve their syscall numbers
///
/// Returns a vector of [Syscall] containing the matches
///
/// # Examples:
/// ```
/// let ssn_array = unsafe{
///      thermite::syscalls::search(|&x| {
///         x.name.starts_with("Nt")
///      }, thermite::syscalls::simple_get_ssn)
///  }.unwrap();
///
///  println!("[^-^] Done! I found {:#?} matching syscalls !", ssn_array.len());
///  if ssn_array.len() < 20 {
///      println!("{ssn_array:#x?}");
///  }
/// ```
pub fn search(
    filter_fn: fn(&&Export) -> bool,
    find_ssn: fn(*const u8) -> Option<u16>,
) -> Result<Vec<Syscall>, DllParserError> {
    let ntdll_handle = unsafe { get_module_address("ntdll.dll") }?;
    let ssns = unsafe { get_all_exported_functions(ntdll_handle) }?
        .iter()
        .filter(filter_fn)
        .filter_map(|x| {
            find_ssn(x.address).map(|ssn| Syscall {
                name: x.name.clone(),
                address: x.address,
                ssn,
            })
        })
        .collect();
    return Ok(ssns);
}

/// Macro used to generate a search pattern for the `syscalls::search` function.
///
/// This call :
/// ```
/// let filter = thermite::syscall_name_match_any!("NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory");
/// ```
///
/// Would expand into the following function:
/// ```
/// let filter = {
///     fn filter(x: &&thermite::models::Export) -> bool {
///            static NAMES: &[&str] = &["NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory"];
///            NAMES.contains(&x.name.as_str())
///     }
/// };
/// ```
///
/// # Example usage:
/// ```
/// use thermite::debug;
/// use thermite::syscalls::{search, simple_get_ssn};
///
/// let filter = thermite::syscall_name_match_any!( "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory" );
///  
/// let tmp_vec = search(
///     filter,
///     simple_get_ssn,
/// ).unwrap();
/// ```
#[macro_export]
macro_rules! syscall_name_match_any {
    ($($name:literal$(,)?)*) => {{
        fn filter(x: &&$crate::models::Export) -> bool {  &[$($name),*].contains(&x.name.as_str()) }
        filter
    }}
}

// This macro takes in any two elements separated by a space replace them by the second one
// Despite what it sounds, it's actually a useful expansion used in `count_args`,
// it allows us to "consume" arguments to count them, replacing them all with the same type valid expression
#[macro_export]
macro_rules! replace_expr {
    ($_t:tt $sub:expr) => {
        $sub
    };
}

/// Macro that takes an arbitrary number of arguments and "returns" how many.
///
/// It is a macro not a function, so it doesn't actually return anything, but expands at compile time into the [`core::slice::len`] function, with an array
/// containing as many elements as there are arguments passed to the macro.
#[macro_export]
macro_rules! count_args {
    ($($args:expr),* $(,)?) => {
        {<[()]>::len(&[$($crate::replace_expr!($args ())),*])} as u32
    }
}

/// Performs a Windows system call.
///
/// This macro will retrieve the syscall number, then call it, passing all the arguments to the system call.
///
/// # Arguments:
///
/// This macro takes only the name of the syscall as parameter.
/// The rest of the arguments being those of the specific syscall.
///
/// # Example usage:
///
/// Demonstrated in the [shellcode injector](src/examples/shellcode_injector.rs) example.
///
#[macro_export]
macro_rules! syscall {
    ($name:literal $(, $args:expr)* $(,)?) => {
         unsafe {
            $crate::syscalls::syscall_handler(
                $crate::syscalls::find_ssn($name).unwrap(),
                thermite::count_args!($($args),*), $($args),*
            )
        };
    }
}
pub unsafe fn find_ssn(name: &str) -> Option<u16> {
	let func_ptr = get_function_address(
		name, get_module_address("ntdll.dll").unwrap(),
	).expect("Function not found in the export table");

	if *(func_ptr as *const [u8; 4]) == [0x4c, 0x8b, 0xd1, 0xb8] {
		let ssn_ptr = ((func_ptr as usize) + 4) as (*const u16);
		Some(*ssn_ptr)
	} else {
		None
	}
}