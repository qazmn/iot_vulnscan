# IoT Firmware Vulnerability Scanner (Lua-focused)

This repository provides a first-pass Lua vulnerability scanner for unpacked firmware images. It detects common risky patterns in Lua source and attempts to decompile Lua bytecode if decompilers are available on the system.

## Usage

```bash
python -m vulnscan.cli /path/to/unpacked/firmware --format json --output report.json
```

### Decompiler support

If the firmware contains Lua bytecode (`.luac`, `.lc`, `.luajit`), the scanner tries these commands (if installed):

- `luadec -o {output} {input}`
- `luadec {input} > {output}`
- `unluac {input} > {output}`

You can override with custom commands:

```bash
python -m vulnscan.cli /path/to/unpacked/firmware \
  --decompiler "luadec -o {output} {input}" \
  --decompiler "unluac {input} > {output}"
```

## Current checks (first version)

- Command injection sinks (`os.execute`, `io.popen`, `luci.sys.exec`, etc.)
- Dynamic code execution (`loadstring`, `load`, `dofile`, `require`)
- Path traversal via file operations (`io.open`, `os.remove`, `nixio.open`, etc.)
- Reflected XSS sinks (`luci.http.write`, `ngx.say`, `ngx.print`)

This is a heuristic scan and should be triaged by a human.
