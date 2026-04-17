# Third-Party Notices

This project distributes a Windows executable bundle that may include third-party runtime components required for packet capture and injection.

## pydivert

- Project: `pydivert`
- Purpose: Python bindings for the WinDivert driver.
- License: `LGPL-3.0-or-later OR GPL-2.0-or-later`
- Source: `https://github.com/ffalcinelli/pydivert`

The release builder copies the installed `pydivert` license files into `third_party_licenses/pydivert/` when they are available in the build environment.

## WinDivert

- Project: `WinDivert`
- Purpose: Windows packet capture and injection driver used by `pydivert`.
- Source: `https://reqrypt.org/windivert.html`

The executable bundle includes the WinDivert binary files provided by the installed `pydivert` package.
