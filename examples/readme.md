# Examples

This project comes with multiple examples aiming to demonstrate various techniques and capabilities of this library.
Some examples are there only as "notes" so that i can keep a trace of techniques or stuff that i learned, you're still
free to check them out although they might be less interesting.

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



