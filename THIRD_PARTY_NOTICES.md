# Third-Party Notices For Windows Portable Development Artifacts

This notice applies to the unsigned AgentGuardian Windows portable development artifact. It is an engineering inventory, not legal advice or proof that every redistribution obligation has been completed.

## Runtime Components

- **CPython 3.12.2** - Python Software Foundation License Version 2.
- **OpenSSL 3.0.13** - Apache License 2.0.
- **PySide6 6.11.1**, **PySide6_Essentials 6.11.1**, **PySide6_Addons 6.11.1**, and **shiboken6 6.11.1** - wheel metadata declares `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`. Qt commercial license has not been verified for this project. Redistribution must satisfy the selected open-source terms or be backed by separately verified commercial rights.
- **Microsoft Visual C++ Runtime 14.38.33126.1** and **Microsoft Universal C Runtime 10.0.19041.1** - license status is `NOASSERTION` pending a Windows redistribution review.

## Build-Time Components

- **PyInstaller 6.16.0** - `GPL-2.0-or-later WITH Bootloader-exception`; the exception permits distributing generated executable bundles under the application's license when dependency licenses are also satisfied.
- The complete build-tool set is listed in `requirements-build.lock`. The CycloneDX SBOM represents PyInstaller as the primary build-time component; other build-only packages are not represented as AgentGuardian runtime imports merely because they participate in the build.

## Distribution Gate

The current portable output is an unsigned development artifact. It is not a signed installer, Windows MVP release, production-safe build, or proof of clean-machine installation. Trusted code signing, native installation, complete license-text packaging, fresh-runner provenance, and uninstall-residue acceptance remain pending.
