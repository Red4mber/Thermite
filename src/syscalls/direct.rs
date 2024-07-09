use std::arch::global_asm;

/*
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

It's quite a smart solution and I take absolutely zero credit for it, I just plundered this stub on GitHub 
                ___go check janoglezcampos/syscall-rs on GitHub___
*/
global_asm!(
    r#"
.global direct_stub
.section .text

direct_stub:
    mov [rsp - 0x8],  rsi       // Backup the value of RSI to the stack
    mov [rsp - 0x10], rdi       // Backup the value of RDI to the stack

    mov eax, ecx                // Move the sycall number to RAX
    mov rcx, rdx                // Move the arguments number in RCX

    mov r10, r8                 // Move syscall Arg1 in R10
    mov rdx, r9                 // Move syscall Arg2 in RDX
    mov  r8,  [rsp + 0x28]      // Move syscall Arg3 in R8
    mov  r9,  [rsp + 0x30]      // Move syscall Arg4 in R9

    sub rcx, 0x4                // Substract 4 from RCX
    jle direct_execute          // If zero or less, skip to the end

    lea rsi,  [rsp + 0x38]      // Move the address of [rsp + 0x38] in RSI
    lea rdi,  [rsp + 0x28]      // Move the address of [rsp + 0x28] in RDI

    rep movsq                   // Move qword from [RSI] to [RDI], repeat RCX times  // Move every stack parameter "down"
direct_execute:
    syscall                     // Perform the Syscall

    mov rsi, [rsp - 0x8]        // Restore value of RSI
    mov rdi, [rsp - 0x10]       // Restore value of RDI
    ret                         // Return
"#
);


#[allow(unused)]
extern "C" {
    /// Imported from the assembly stub
    ///
    /// Not made to be called directly, it is better to use the [`thermite::syscall`] macro.
    ///
    /// ### Arguments :
    ///  - `ssn` : 16-bit unsigned int, the System Service Number of the syscall you want to call
    ///  - `arg_count`: 32-bit unsigned int, refers to the count of arguments to pass to syscall (excluding these two, which are not passed to syscall)
    ///  - ...  -> Then, every argument to pass to the syscall instruction.
    pub fn direct_stub(ssn: u16, arg_count: u32, ...) -> i32;
}


/// Performs a direct system call.
///
/// This macro will retrieve the syscall number, then perform the syscall, passing it all the arguments.
///
/// Demonstrated in the [shellcode injector](src/examples/shellcode_injector.rs) example.
///
#[macro_export]
macro_rules! direct_syscall {
    ($name:literal $(, $args:expr)* $(,)?) => {
         unsafe {
            $crate::syscalls::direct::direct_stub(
                $crate::syscalls::find_single_ssn($name).unwrap(),
                thermite::count_args!($($args),*),
                $($args),* )
        }
    }
}

