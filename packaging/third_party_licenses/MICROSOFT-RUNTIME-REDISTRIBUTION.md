# Microsoft Runtime Redistribution Record

The Windows payload contains unmodified app-local Microsoft runtime files
collected from the hash-locked CPython and PySide wheels, including UCRT,
VCRUNTIME140, and MSVCP140-family DLLs. Their exact paths, sizes, and SHA256
digests are recorded in `PAYLOAD-MANIFEST.json` and `SHA256SUMS`.

Microsoft states that distribution of the Visual C++ Runtime package or
individual binaries is limited to licensed Visual Studio users and remains
subject to the applicable Microsoft Software License Terms. Microsoft also
lists the Visual C++ runtime files as distributable, unmodified, with a
program when those terms are satisfied.

Authoritative references:

- `https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files?view=msvc-170`
- `https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution`
- `https://visualstudio.microsoft.com/license-terms/`

Before public Release publication, the publisher must confirm that the final
artifact was produced and distributed under an applicable valid Visual Studio
license. This engineering record does not itself grant that license and does
not replace the publisher's acceptance of Microsoft's terms.
