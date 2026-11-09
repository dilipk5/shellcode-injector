# Remote Shellcode Injector

A minimal Windows (x64) tool that reads a raw shellcode file and injects it
into a running process by name, then executes it via `CreateRemoteThread`.

## How it works

1. Snapshots running processes (`CreateToolhelp32Snapshot`) and finds the
   target by name, saving its PID.
2. Opens the target with `OpenProcess` (all access).
3. Allocates RW memory in the target with `VirtualAllocEx`.
4. Copies the shellcode in with `WriteProcessMemory`.
5. Flips the region to RWX with `VirtualProtectEx`.
6. Spawns a thread at the shellcode address with `CreateRemoteThread`.

## Usage
```
program.exe <shellcode.bin> <TargetProcess.exe>
```
<img width="2074" height="1173" alt="image" src="https://github.com/user-attachments/assets/4e641b80-bd65-426e-8b45-400e8f08b7e3" />
