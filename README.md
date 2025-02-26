# MemLite
A lightweight, bloat-free x86/x64 Windows process memory library that's ***header-only***.

---

## Usage:

```cpp
// retrieves the id of the process with the name "notepad.exe".
const auto pid = mem_lite::util::get_pid( "notepad.exe" );

// instantiates a 'mem_lite::process' instance using the id.
mem_lite::process<mem_lite::windows_api> process( pid );

// ensures instance was initialized.
if ( !process.valid() )
  return 0;

// allocates a page of virtual memory.
const auto address = process.alloc(0x1000);

// writes to the corresponding virtual address.
process.write(address, 0xDEADBEEF);

// reads the corresponding virtual address.
const auto buffer = process.read(address);
```
