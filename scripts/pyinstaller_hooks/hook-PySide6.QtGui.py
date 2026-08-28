from PyInstaller.utils.hooks.qt import add_qt6_dependencies

from scripts.build_windows_portable import filter_qt_gui_binaries


hiddenimports, binaries, datas = add_qt6_dependencies(__file__)
binaries = list(filter_qt_gui_binaries(binaries))
