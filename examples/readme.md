# Examples

This project comes with multiple examples aiming to demonstrate various techniques and capabilities of this library.
Some examples are there only as "notes" so that i can keep a trace of techniques or stuff that i learned,
while others are "scratchpads" or sketches of functionnalities i plan to add in the library but would like to work on a
little before commiting to it.

All of the examples here can be compiled and launched using cargo from the root directory of this project.

### [Shellcode Injector](/examples/shellcode_injector.rs)

This example aims to demonstrate the use of Thermite to perform a rather simple shellcode injection using direct
syscalls.

```bash
cargo run --package thermite --example shellcode_injector <Target PID>
```

### [DLL Injector](/examples/dll_injector.rs)

This example is very similiar to the previous one, it aims to demonstrate the use of Thermite to perform a DLL injection
using direct syscalls.

```bash
cargo run --package thermite --example dll_injector <Target PID> C:\absolute\path\to\your.dll
```

### [Halo's Gate](/examples/halos_gate.rs)

A technique originally created by Reenz0h, build upon the Hells Gate technique to dynamically retrieve syscall IDs of
hooked syscalls by looking at its neighbors.

```bash
cargo run --package thermite --example halos_gate.rs
```

### [FreshyCalls](/examples/freshycalls.rs)

[FreshyCalls on GitHub](https://github.com/crummie5/FreshyCalls)

This is an example to show how to dynamically retrieve syscall IDs by sorting syscalls by address, then assigning them
all an ID in order.
This example also includes code to verify the IDs are valid.

```bash
cargo run --package thermite --example freshycalls.rs
```

### [ETW Patcher](/examples/etw_patcher.rs)

Work in progress

This example aims to demonstrate current techniques for bypassing ETW.
So far only the most basic local ETW patching has been implemented, but the other should arrive soon.

```bash
cargo run --package thermite --example etw_patching.rs
```