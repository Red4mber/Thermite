# Thermite: Offensive Rust

This project aims to showcase various techniques for EDR/AV Evasion and malware development in rust.

It is written entirely in Rust and so far I tried as much as possible to make everything myself.

## Summary

So far only a small part of this project is complete, but it is already capable to showcase basic malware development
techniques, such as :

* PEB Walking and enumeration using custom implementation of GetModuleHandle/GetProcAddress
* Direct syscalls with dynamic syscall ID retrieval using a mix of techniques such as Hell's Gates and Halo's Gate (see
  in [Examples](./examples/readme.md)).
* Indirect syscalls, you can now pick between the two by including either one or the other macro, like so :
  * `use thermite::indirect_syscall as syscall;` or `use thermite::direct_syscall as syscall;`

The two being completely interchangeable, feel free to test both.

I also began implementing various techniques such as process enumeration, etw/amsi patching, PPID spoofing etc... You'll
find most of these in the example directory.

### Go check out the code :D

The goal of this project is to teach myself malware development, to that end, I took care to document everything and
wrote detailed comments and documentation for this project. This is why i really invite anyone to go check out the code,
I learned a lot while making this, maybe you could too, who knows ?

After all, knowledge is meant to be shared <3

## Why the name ?

What is thermite if not offensive rust ?

Also, it's cool and all cool projects need a cool name.

## License

Nah, just take it

Just don't be evil :)
