# MemLite
A header-only, lightweight x86/x64 Windows process memory library.
## Usage:
```cpp
// returns id of process with the name "notepad.exe".
const DWORD pid = memlite::util::get_pid( L"notepad.exe" );

// instantiates a 'memlite::process' instance using the id.
memlite::process process( pid );

// allocates virtual memory of provided specifications.
const void* address = process.alloc( 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

// reads the corresponding virtual address.
const int buffer = process.read( address );

// writes to the corresponding virtual address.
process.write( address, 0xDEADBEEF );

// injects a module on disk.
process.load_image( "path_to_module.dll" );

// returns pointer to struct containing module info.
const auto kernel32 = process.get_module( L"kernel32.dll" );

// returns virtual address of exported function.
const auto load_lib = process.get_proc_address( kernel32, "LoadLibraryA" );

// scans a module for a given pattern (jmp [rbx] instruction in this case).
jmp_rbx = process.find_pattern( mod, "FF 23" );
```
