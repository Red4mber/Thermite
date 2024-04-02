# Thermite: Offensive Rust

This project aims to showcase various techniques for EDR/AV Evasion and malware development in rust.

It is written entirely in Rust and so far I tried as much as possible to make everything myself.

## Summary

So far only a small part of this project is complete, but it is already capable to showcase basic malware development
techniques, such as :

* PEB Walking and enumeration using custom implementatiion of GetModuleHande/GetProcAddress
* Direct syscalls with dynamic syscall ID retrieval using a mix of techniques such as Hell's Gates and Halo's Gate (see
  in [Examples](./examples/readme.md)).

I am currently working on implementing indirect system calls, and will probably publish it soon.

## Usage

You can easily add the project as dependency to your rust project using `cargo` :

```
cargo add --git https://github.com/Red4mber/Thermite
```

Then you can use the project in any way you like, i suggest taking a look at the [examples](./examples/readme.md) to see
the various ways in which this can be useful to your project.

Most of the functionnalities are abstracted behind a single easy to use syscall macro, which will automatically perform
the required preparation such as resolving the syscall ID.

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
