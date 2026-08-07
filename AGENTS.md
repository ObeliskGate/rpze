# AGENTS.md

## Project Overview

rpze (Remote Python, Zombie Endless) is a Python + C++ hybrid framework for TAS/modding and I, Zombie Endless (IZE) testing of Plants vs. Zombies (PvZ). It communicates with an injected DLL via IPC shared memory to achieve 100% precision game control from Python.

**Platform**: Windows 10+ only, CPython >= 3.11

**Architecture**:
- `src/rpze/` — Python package (installed as `rpze`)
  - `basic/` — DLL injection, game launch, assembly utilities
  - `structs/` — PvZ in-game data structure wrappers
  - `flow/` — Coroutine-like test flow control
  - `iztest/` — IZE test runner and helper functions
  - `examples/` — Example test scripts
- `rp_dll/` — C++ 32-bit DLL injected into PvZ (uses minhook)
- `rp_extend/` — C++ pybind11 extension module (Python ↔ game bridge)
- `rp_injector/` — C++ 32-bit injector executable
- `sharedinc/` — Shared C++ headers (IPC shared memory definitions)

## Setup Commands

Prerequisites: [xmake](https://xmake.io), MSVC (Visual Studio 2022), [uv](https://docs.astral.sh/uv/)

```powershell
# Clone and enter project
git clone https://github.com/ObeliskGate/rpze.git
cd rpze

# Create venv and install in editable mode
uv sync

# Set game path (or create .env with RP_GAME_PATH="path\to\PlantsVsZombies.exe")
$env:RP_GAME_PATH = "C:\path\to\PlantsVsZombies.exe"
```

## Build Commands

```powershell
# Build the wheel (includes C++ compilation via xmake)
uv build --python 3.11   # or 3.12, 3.13, 3.14

# Configure xmake with correct arch for current Python
python hatch_build.py

# Build C++ targets only (after xmake config)
xmake

# Rebuild C++ targets
xmake -r

# Clean build artifacts
xmake c
```

The build hook in `hatch_build.py` automatically:
1. Detects Python bitness (32-bit → x86, 64-bit → x64)
2. Runs `xmake f -a <arch> -m release -c -y`
3. Runs `xmake -r` to compile all C++ targets
4. Copies outputs: `rp_dll.dll` and `rp_injector.exe` → `src/rpze/bin/`, `rp_extend.*.pyd` → `src/rpze/`

## C++ Build Targets

| Target | Arch | Kind | Description |
|--------|------|------|-------------|
| `rp_dll` | x86 | shared library | DLL injected into 32-bit PvZ process |
| `rp_extend` | x64 (matches Python) | pybind11 module | Python extension for game control |
| `rp_injector` | x86 | binary | Injects rp_dll into PvZ |

All C++ targets use C++23 and MSVC. The `rp_dll` target also supports MinGW (i386) on the `stacktrace` branch.

## Testing

There is no formal test framework (no pytest/unittest). Testing is done by running scripts against a live PvZ game instance:

```powershell
# Verify installation works
python -m rpze --path "path\to\PlantsVsZombies.exe"

# Run a test script (e.g., main.py at repo root)
python main.py
```

Tests require PvZ version 1.0.0.1051 (English, from [pvz.tools](https://pvz.tools/download/)) running on the same machine.

## Code Style — Python

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Every file starts with `# -*- coding: utf_8 -*-`
- Use **relative imports** within the `rpze` package
- Blank line between stdlib imports and project imports
- All public functions must have **type hints** and **docstrings**
- Docstrings are written in **Chinese** using Google-style sections (`Args`, `Returns`, `Raises`, `Examples`)
- Single underscore prefix (`_name`) marks protected members — no compatibility guarantee
- Zero warnings policy: suppress with `# type: ignore` or `# noqa` when necessary
- Do not use Chinese punctuation (use ASCII `,` `.` `:` etc.)

Example:
```python
# -*- coding: utf_8 -*-
"""
模块简述
"""
import os
from pathlib import Path

from .exception import PvzStatusError
from ..rp_extend import Controller


def some_function(arg: int) -> str:
    """
    函数简述

    Args:
        arg: 参数说明
    Returns:
        返回值说明
    Raises:
        ValueError: 异常说明
    """
    ...
```

## Code Style — C++

- C++23 standard
- MSVC compiler (Visual Studio 2022)
- clangd for IDE support (compile_commands.json in `.vscode/`)
- Precompiled headers via `set_pcxxheader` in xmake
- `NOMINMAX` defined for Windows headers
- UTF-8 source encoding (`set_encodings("utf-8")`)
- LTO enabled in release/releasedbg modes
- Warnings set to `allextra` in release builds

## File Organization

```
rpze/
├── xmake.lua              # Root build file (includes sub-targets)
├── pyproject.toml         # Python package metadata (hatchling)
├── hatch_build.py         # Custom build hook (xmake integration)
├── get_hash.py            # SHA256 hash generator for built binaries
├── src/rpze/              # Python source
│   ├── __init__.py        # Version string
│   ├── __main__.py        # `python -m rpze` entry point
│   ├── rp_extend.pyi      # Type stubs for the C++ extension
│   ├── bin/               # Built binaries (rp_dll.dll, rp_injector.exe)
│   └── ...
├── rp_dll/                # C++ DLL source
├── rp_extend/             # C++ pybind11 extension source
├── rp_injector/           # C++ injector source
├── sharedinc/             # Shared C++ headers (shm.h, dllexport.h)
├── .env                   # Local env vars (RP_GAME_PATH)
└── main.py                # Dev test script
```

## Environment Variables

- `RP_GAME_PATH` — Path to `PlantsVsZombies.exe`. Used by `python -m rpze` and `InjectedGame()`. Can be set in `.env` file (loaded via python-dotenv).

## Dependencies

Python (runtime):
- `keystone-engine` >= 0.9.2 — x86 assembler for runtime code generation
- `python-dotenv` >= 1.2.1 — .env file loading

C++ (managed by xmake):
- `minhook` >= 1.3.4 — API hooking library (for rp_dll)
- `pybind11` >= 3.0.1 — Python/C++ binding (for rp_extend)

## Pull Request Guidelines

- Target the **`dev`** branch (never push directly to `master`)
- Follow all code style rules above
- Ensure zero warnings in both Python and C++ code
- Keep commits focused and descriptive

## Debugging Tips

- The `.vscode/compile_commands.json` is auto-generated by xmake for clangd
- `.clangd` at root disables UnusedIncludes/MissingIncludes diagnostics
- `rp_injector/.clangd` may have additional per-target overrides
- `result.log` at root contains test output logs
- If the game crashes on injection, verify PvZ version is exactly 1.0.0.1051 (English, lcx version from pvz.tools)
- `get_hash.py` generates `.sha256` files for built binaries — these are checked at runtime to detect stale builds

## License

GPLv3
