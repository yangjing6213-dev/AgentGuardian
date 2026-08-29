# Third-Party Notices For AgentGuardian 0.3 Windows Public Preview

This notice applies to the unsigned AgentGuardian 0.3 Windows Public Preview installer and portable artifact. It is an engineering inventory, not legal advice. Exact component versions are generated into the packaged copy from the same specifications used to produce `AgentGuardian.cdx.json`. Confirmed license materials for the packaged toolchain and Qt route, Qt attributions, source archive hashes, and LGPL replacement instructions are included in `THIRD_PARTY_LICENSES/` inside the installed payload. The packet is not a complete per-package copyright and notice bundle for every transitive Python runtime dependency; the generated component inventory and CycloneDX SBOM record those dependencies and their license expressions.

<!-- AGENTGUARDIAN_COMPONENT_INVENTORY_START -->

The artifact-specific component inventory is generated during the Windows build.

<!-- AGENTGUARDIAN_COMPONENT_INVENTORY_END -->

## License And Redistribution References

- **CPython** - Python Software Foundation License Version 2. Official terms: <https://docs.python.org/3.12/license.html>.
- **OpenSSL 3.x** - Apache License 2.0. Official terms: <https://openssl-library.org/source/license/>.
- **PyInstaller and its embedded bootloader** - `GPL-2.0-or-later WITH Bootloader-exception`. Official terms: <https://pyinstaller.org/en/stable/license.html>.
- **PySide6, PySide6_Essentials, PySide6_Addons, shiboken6, and Qt libraries** - this preview selects the `LGPL-3.0-only` route for the dynamically linked Qt runtime. No Qt commercial license is claimed. See `THIRD_PARTY_LICENSES/QT-LGPL-COMPLIANCE.md`, the bundled GPL/LGPL texts, and the exact Qt 6.11.1 attribution inventory. Official overview: <https://doc.qt.io/qt-6/licensing.html>.
- **Microsoft Visual C++ Runtime and Microsoft Universal C Runtime** - represented as `NOASSERTION` in the SBOM. The exact app-local DLLs are covered by the payload manifest. Public distribution still requires the publisher to satisfy Microsoft's licensed-user and unmodified-file terms described in `THIRD_PARTY_LICENSES/MICROSOFT-RUNTIME-REDISTRIBUTION.md`. Official guidance: <https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170>.
- **Inno Setup 7.0.2** - build-time installer generator. The installer output identifies Inno Setup and this project records the upstream license without claiming ownership of Inno Setup. Official terms: <https://jrsoftware.org/files/is/license.txt>.

The complete Python runtime closure and its exact versions are listed in the generated inventory and CycloneDX SBOM. The MCP Python SDK distribution contains optional HTTP transport modules in its dependency graph. AgentGuardian 0.3 registers and starts only STDIO; the presence of dependency code is not evidence that AgentGuardian exposes a listener.

The portable build's internal `BUILD-METADATA.json` intentionally uses `unsigned_development_only` to identify a build-stage artifact. Release staging separately uses `unsigned_public_preview` for the external delivery channel. These labels are deliberately different and do not imply signing, production safety, or complete legal clearance.

## Public Preview Boundary

The current output is an unsigned Public Preview. It is not a signed installer, a production-safety claim, or authorization to process high-sensitivity real data. Code signing remains deferred. Exact-SHA CI, clean-machine lifecycle evidence, integrity verification, and the publisher's Microsoft runtime license confirmation remain separate release gates.
