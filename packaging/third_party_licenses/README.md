# Third-Party License Packet

This directory is copied unchanged into every AgentGuardian Windows payload as
`THIRD_PARTY_LICENSES/`. It records the license material used by the unsigned
0.3 Public Preview build; it is not legal advice.

- `QT-LGPL-COMPLIANCE.md` records the selected Qt LGPL route, exact source
  archives, dynamic-library layout, and replacement instructions.
- `QT-THIRD-PARTY-ATTRIBUTIONS.json` is generated from the exact Qt 6.11.1,
  Qt SVG 6.11.1, and PySide 6.11.1 official source archives.
- `qt-licenses/` contains the open-source license texts from those verified
  archives. The Qt commercial license text is intentionally excluded because
  this project does not claim a commercial Qt license.
- `PYTHON-3.12.txt`, `PYINSTALLER-6.16.0.txt`, `OPENSSL-3.0.txt`, and
  `INNO-SETUP-7.0.2.txt` preserve the relevant upstream terms.
- `MICROSOFT-RUNTIME-REDISTRIBUTION.md` records the remaining publisher-side
  condition for the app-local Microsoft runtime DLLs.

The generated `AgentGuardian.cdx.json`, `PAYLOAD-MANIFEST.json`, and
`SHA256SUMS` bind this packet to the exact delivered payload.
