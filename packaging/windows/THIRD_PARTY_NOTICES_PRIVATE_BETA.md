# Third-Party Notices For AgentGuardian 0.2.0 Personal Private Beta

This notice applies only to the unsigned AgentGuardian 0.2.0-beta.1 Personal v1
private-beta installer and portable artifact. It is an engineering inventory,
not legal advice or proof that every redistribution obligation has been
completed. Exact component versions are generated into the packaged copy from
the same specifications used to produce `AgentGuardian.cdx.json`.

<!-- AGENTGUARDIAN_COMPONENT_INVENTORY_START -->

The artifact-specific component inventory is generated during the Windows build.

<!-- AGENTGUARDIAN_COMPONENT_INVENTORY_END -->

## License And Redistribution References

- **CPython** - Python Software Foundation License Version 2. Official terms:
  <https://docs.python.org/3.12/license.html>.
- **OpenSSL 3.x** - Apache License 2.0. Official terms:
  <https://openssl-library.org/source/license/>.
- **PyInstaller and its embedded bootloader** - `GPL-2.0-or-later WITH
  Bootloader-exception`. Official terms:
  <https://pyinstaller.org/en/stable/license.html>.
- **PySide6, PySide6_Essentials, PySide6_Addons, shiboken6, and Qt libraries**
  - package metadata declares `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`.
  Qt commercial license has not been verified for this project. Redistribution
  must satisfy the selected open-source terms or be backed by separately
  verified commercial rights. Official overview:
  <https://doc.qt.io/qt-6/licensing.html>.
- **Microsoft Visual C++ Runtime and Microsoft Universal C Runtime** -
  represented as `NOASSERTION` until a reviewer confirms that the exact
  binaries and build environment meet Microsoft's redistribution terms.
  Official guidance:
  <https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170>.
- **Inno Setup 7.0.2** - build-time installer generator. The installer output
  identifies Inno Setup and this project records the upstream license without
  claiming ownership of Inno Setup. Official terms:
  <https://jrsoftware.org/files/is/license.txt>.

The complete Python runtime closure and its exact versions are listed in the
generated inventory and CycloneDX SBOM. The license packet is the reviewed
source material copied into the payload; it is not a complete per-package
copyright and notice bundle for every transitive Python runtime dependency.

Personal v1 permanently excludes MCP runtime integration. This private-beta
channel does not expose a local MCP service or claim compatibility with the
0.3 integrations-preview channel.

## Distribution Gate

The current output is an unsigned private-beta development artifact for a
personal non-regulated configuration. It is not a signed installer, a
production-safety claim, or authorization to process high-sensitivity real
data. Code signing, final legal review, clean-machine installation, and
uninstall-residue acceptance remain separate release evidence.
