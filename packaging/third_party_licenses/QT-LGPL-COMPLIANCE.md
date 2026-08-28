# Qt 6.11.1 LGPL Compliance Record

AgentGuardian 0.3 Public Preview uses the open-source `LGPL-3.0-only` option
for PySide6, shiboken6, and the Qt libraries. No Qt commercial license is
claimed.

## Dynamic Linking

The Windows payload keeps Qt and PySide as replaceable shared libraries. The
primary Qt libraries observed in the release payload are:

- `_internal/PySide6/Qt6Core.dll`
- `_internal/PySide6/Qt6Gui.dll`
- `_internal/PySide6/Qt6Svg.dll`
- `_internal/PySide6/Qt6Widgets.dll`

PySide wrapper DLLs, shiboken DLLs, and Qt plugins remain separate files under
`_internal/PySide6/` and `_internal/shiboken6/`. AgentGuardian does not apply a
runtime signature or hash lock that prevents a user from replacing compatible
Qt, PySide, shiboken, or plugin binaries. The payload manifest is an integrity
record for the publisher's original build, not an access-control mechanism.

To replace the libraries, stop AgentGuardian and its MCP process, preserve a
backup of the installation directory, build or obtain interface-compatible
Qt/PySide/shiboken 6.11.1 shared libraries from the sources below, and replace
the corresponding DLL/PYD/plugin files while preserving their names and
relative paths. Modified libraries are unsupported by the AgentGuardian
publisher, but the installer does not prohibit this replacement. A later
upgrade may restore the publisher-provided files.

## Exact Source Archives

- Qt Base 6.11.1:
  `https://download.qt.io/official_releases/qt/6.11/6.11.1/submodules/qtbase-everywhere-src-6.11.1.zip`
  SHA256 `3529cc37297a5a7aae4486843b9fd41c30df1d79a770f85e240b537dcc327ca5`
- Qt SVG 6.11.1:
  `https://download.qt.io/official_releases/qt/6.11/6.11.1/submodules/qtsvg-everywhere-src-6.11.1.zip`
  SHA256 `767730188d4610a89bf8da502f87acf1c8881a3ac54f1e0eb167ab1e08b03a75`
- Qt for Python / PySide 6.11.1:
  `https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.11.1-src/pyside-setup-everywhere-src-6.11.1.zip`
  SHA256 `d9f2e86726a1f6d756323be74a890786aa546d5e8fa457ced3117f4418a5388b`

AgentGuardian does not modify those upstream libraries. The application source
is published at `https://github.com/yangjing6213-dev/AgentGuardian`.

## Included Terms And Attributions

The complete GPL 3.0 and LGPL 3.0 texts are present in `qt-licenses/` together
with the other open-source license texts shipped by the verified source
archives. `QT-THIRD-PARTY-ATTRIBUTIONS.json` records the Qt Core, Qt GUI, Qt
SVG, and Qt for Python attributions extracted from those same archives.

Official licensing overview: `https://doc.qt.io/qt-6/licensing.html`.
