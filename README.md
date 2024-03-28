# Thermite: Offensive Rust

## A Rust Malware development Learning Project

This is a **learning project** aimed at exploring advanced topics in Windows internals, malware development and EDR/AV
evasion techniques. It is written entirely in Rust and so far does not any dependencies at all.

I do not have any ambition for this project to become a game-breaking tool for red-teams or a high take research project
pushing the limits of EDRs, I just do it for the joy of it and to learn cool tricks, I don't even know why you're
reading this to be honest

## Features

Well, so far not much ^-^"
But it's been a week since I started coding, so chill out, it won't be ready soon.

I finished working on parsing loaded DLLs in memory to extract export function, then wrote a (very)basic function to
dynamically retrieve Syscall numbers.
The assembly part is done, so you should be able to use it to make direct syscalls, but I still need to work on it a
little, mostly to clean it up.

I'll probably work on indirect syscalls next, as it seems like the logical thing to do, but I don't plan much, so far I've been completely winging it, and the result is pretty fine.

Feel free to browse the code, I took care to document absolutely everything and wrote detailed documentation for every
function so far.

I learned a lot while making this, maybe you too, who knows ?
Knowledge is meant to be shared <3

### Why rust ?

I just think its neat.

I admit that it doesn't make it easy, but that exactly what makes learning a new thing fun, so why not ?

## License

Nah, just take it

## Disclaimer

Just don't be evil.
