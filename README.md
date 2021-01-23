# Key Stretcher
Make a password more secure against a brute-force attack.

## Quick start
- Install [.NET 5.0 SDK](https://dotnet.microsoft.com/download/dotnet/5.0)
- Start the program: `dotnet run`

## Command line arguments
| Argument | Description |
| --- | --- |
| -N | Scrypt CPU/memory cost |
| -r | Scrypt block size |
| -p | Scrypt parallelization |
| -t | Scrypt threads (can be modified without affecting the hash) |
| -m | Argon2 memory size in KiB |
| -i | Argon2 iterations |
| -d | Argon2 degree of parallelism |
| -s | Salt (used by both Scrypt and Argon2) |

Example usage: `dotnet run -- -N1024 -r8 -p1 -t1 -i1 -m1024 -d1 -ssomesalt`

## Extra information
This application computes both the [Scrypt](https://en.wikipedia.org/wiki/Scrypt) hash and the [Argon2d](https://en.wikipedia.org/wiki/Argon2) hash of the submitted password. The same salt is used in both cases. The hashes are then combined using the XOR operator into a final hash consisting of 32 bytes.

This application does not provide any protection against [side-channel attacks](https://en.wikipedia.org/wiki/Side-channel_attack). If you need protection against such attacks, then remove Scrypt and use the class `Argon2i` or `Argon2id` instead of the class `Argon2d` (see `Program.cs`).