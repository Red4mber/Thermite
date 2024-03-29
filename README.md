# Thermite: Offensive Rust

## A Rust Malware development Learning Project

This is a **learning project** aimed at exploring advanced topics in Windows internals, malware development and EDR/AV
evasion techniques. It is written entirely in Rust and so far does not any dependencies at all.

I do not have any ambition for this project to become a game-breaking tool for red-teams or a high take research project
pushing the limits of offensive security as we know it, I just do it for the joy of it and to learn rust programming and some cool hacking tricks 

## Features

The library is already capable of performing direct syscalls, with dynamic system service number retrieval.
In the examples folder, there is a file showcasing it's capabilities with a shellcode injector using syscalls.

so far it does not support 32bit architecture and there's still a lot of stuff that have yet to be implemented, the road is long had of me.

Feel free to browse the code, I took care to document absolutely everything and wrote detailed comments and documentation for almost everything in the crate.

I learned a lot while making this, maybe you too, who knows ?
Knowledge is meant to be shared <3

### Why rust ?

I just think its neat.

I admit that it doesn't make it easy, but that exactly what makes learning a new thing fun, so why not ?

## License

Nah, just take it

## Disclaimer

Just don't be evil :)
