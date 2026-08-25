# Third-Party Notices For Windows Portable Development Artifacts

This notice applies to the unsigned AgentGuardian Windows portable development artifact. It is an engineering inventory, not legal advice or proof that every redistribution obligation has been completed.

## Runtime Components

- **CPython 3.12.2** - Python Software Foundation License Version 2.
- **OpenSSL 3.0.13** - Apache License 2.0.
- **PyInstaller Bootloader 6.16.0** - `GPL-2.0-or-later WITH Bootloader-exception`; the bootloader is embedded in `AgentGuardian.exe`, and the exception permits distributing generated executable bundles under the application's license when dependency licenses are also satisfied.
- **PySide6 6.11.1**, **PySide6_Essentials 6.11.1**, **PySide6_Addons 6.11.1**, and **shiboken6 6.11.1** - wheel metadata declares `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`. Qt commercial license has not been verified for this project. Redistribution must satisfy the selected open-source terms or be backed by separately verified commercial rights.
- **Microsoft Visual C++ Runtime 14.38.33126.1** and **Microsoft Universal C Runtime 10.0.19041.1** - license status is `NOASSERTION` pending a Windows redistribution review.

### Python Runtime Closure

The following 34 Python distributions are the reviewed runtime closure of
`PySide6` plus `mcp==2.0.0` for the Windows 3.12 build lock. Versions are
locked in `requirements-build.lock` and the names below follow the lock's
distribution names.

| Distribution | Version | SPDX expression |
| --- | --- | --- |
| `annotated-types` | 0.8.0 | MIT |
| `anyio` | 4.14.2 | MIT |
| `attrs` | 26.1.0 | MIT |
| `cffi` | 2.1.1 | MIT-0 |
| `click` | 8.4.2 | BSD-3-Clause |
| `colorama` | 0.4.6 | BSD-3-Clause |
| `cryptography` | 50.0.0 | Apache-2.0 OR BSD-3-Clause |
| `h11` | 0.16.0 | MIT |
| `httpcore2` | 2.12.0 | BSD-3-Clause |
| `httpx2` | 2.12.0 | BSD-3-Clause |
| `idna` | 3.19 | BSD-3-Clause |
| `jsonschema` | 4.26.0 | MIT |
| `jsonschema-specifications` | 2025.9.1 | MIT |
| `mcp` | 2.0.0 | MIT |
| `mcp-types` | 2.0.0 | MIT |
| `opentelemetry-api` | 1.44.0 | Apache-2.0 |
| `pydantic` | 2.13.4 | MIT |
| `pydantic-core` | 2.46.4 | MIT |
| `pycparser` | 3.0 | BSD-3-Clause |
| `pyjwt` | 2.13.0 | MIT |
| `pyside6` | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only |
| `pyside6-addons` | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only |
| `pyside6-essentials` | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only |
| `python-multipart` | 0.0.32 | Apache-2.0 |
| `pywin32` | 312 | PSF-2.0 |
| `referencing` | 0.37.0 | MIT |
| `rpds-py` | 2026.6.3 | MIT |
| `shiboken6` | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only |
| `sse-starlette` | 3.4.8 | BSD-3-Clause |
| `starlette` | 1.6.0 | BSD-3-Clause |
| `truststore` | 0.10.4 | MIT |
| `typing-extensions` | 4.16.0 | PSF-2.0 |
| `typing-inspection` | 0.4.4 | MIT |
| `uvicorn` | 0.52.4 | BSD-3-Clause |

The MCP Python SDK distribution contains optional HTTP transport modules in its
dependency graph. AgentGuardian 0.3 registers and starts only STDIO; the
presence of dependency code is not evidence that AgentGuardian exposes a
listener. License and redistribution review remains a release gate.

## Build-Time Components

- **PyInstaller 6.16.0** - the packaging tool is represented separately from its embedded runtime bootloader in the CycloneDX SBOM.
- The complete build-tool set is listed in `requirements-build.lock`. The CycloneDX SBOM represents PyInstaller as the primary build-time component; other build-only packages are not represented as AgentGuardian runtime imports merely because they participate in the build.

## Distribution Gate

The current portable output is an unsigned development artifact. It is not a signed installer, Windows MVP release, production-safe build, or proof of clean-machine installation. Trusted code signing, native installation, complete license-text packaging, fresh-runner provenance, and uninstall-residue acceptance remain pending.
