# repackager

**WARNING: Currently in the alpha stage.**

A simple CLI tool for MSIX packaging and package identity on Windows. Its main
focus is sparse packages with external payloads and loose packages registered
from application directories. It also provides commands to inspect executables,
read MSIX packages, edit manifests, and manage package registration. It can be used
together with Microsoft's own MSIX utilities.

## Requirements

- Windows with support for the package registration APIs used by the tool.
- Developer Mode enabled for unsigned development package registration.
- Visual Studio 2022, CMake 3.20 or later, to build from source.
- Windows SDK tools.

Run the commands below in PowerShell from the repository directory. If you work
from WSL, keep the source and build directories on a Windows-local drive and use
Windows tools for the build and package operations.

## Build and test

```powershell
cmake.exe -S . -B out-Release -G "Visual Studio 17 2022" -A x64
cmake.exe --build out-Release --config Release
ctest.exe --test-dir out-Release -C Release --output-on-failure

$repackager = (Resolve-Path .\out-Release\Release\repackager.exe).Path
& $repackager help
```

Tests are enabled by default. Set `-DREPACKAGER_BUILD_TESTS=OFF` at configuration
time to omit them. The default build uses Windows Appx Packaging APIs for MSIX
package I/O. The optional `REPACKAGER_USE_MSIX_SDK` build option is experimental;
use the default build for the examples below.

## Main workflows

Choose a new package name for each converted application. The default publisher
is `CN=Repackager`. Commands print the resulting package identity and AUMID.

### Copy a Win32 application into a sparse layout

```powershell
& $repackager retrofit-win32-sparse --source 'C:\Apps\Example' --executable 'Example.exe' --output 'C:\Packages\Example' --name Example.Sparse --prepare-only
```

The output directory must be absent or empty. The workflow copies the source
files, adds package identity to the copied executable, generates logo assets and
a sparse manifest, and writes operation records. It checks that the source
executable has not changed.

The generated layout contains:

```text
Example/
  payload/                 Copied application files, including the patched EXE
  identity/
    AppxManifest.xml
    Assets/                Generated package logos
  .repackager/             Receipt and operation journal
```

`--executable` accepts a path relative to the source directory or an absolute
path inside it. The manifest stores a package-relative executable path.

`--prepare-only` creates the layout without registration. Register it later with:

```powershell
& $repackager register-sparse --manifest 'C:\Packages\Example\identity\AppxManifest.xml' --external 'C:\Packages\Example\payload'
```

Omit `--prepare-only` to register during conversion. Add `--launch` to start the
copied executable after registration. Keep both the identity and payload
directories at their registered locations while the package is in use.

If the source executable has an Authenticode signature, pass
`--accept-signature-loss` to permit removal of the signature from the copied
executable. The sparse conversion commands also accept `--publisher` and
`--signing-thumbprint` to sign the patched executable. The certificate must be in
`CurrentUser\My`, its subject must match the publisher, and the signed executable
must pass SignTool trust verification.

### Register a Win32 application in place as a loose package

```powershell
& $repackager retrofit-win32-inplace --directory 'C:\Apps\Example' --executable 'Example.exe' --name Example.Loose --prepare-only
& $repackager register-loose --manifest 'C:\Apps\Example\AppxManifest.xml'
```

This workflow creates a manifest, assets, and a receipt in the application
directory. It keeps the executable bytes unchanged. The directory must have no
existing `AppxManifest.xml` or conflicting tool-owned paths. Write operations in
protected directories can request elevation.

Omit `--prepare-only` to register during conversion. With `--launch`, this
workflow activates the application through its AUMID. `--appcontainer` selects
AppContainer execution; many classic Win32 applications need the default medium
integrity execution mode.

After registration, Windows treats the loose directory as package content.
Changes to its files can mark the package as modified and cause a repair prompt.

### Convert an installed MSIX application into a sparse layout

First obtain the source package full name:

```powershell
& $repackager list-msix
& $repackager retrofit-msix-sparse --package-full-name 'Example_1.0.0.0_x64__publisherid' --output 'C:\Packages\ExampleClone' --name Example.Clone --prepare-only
```

Replace the sample full name with a value from `list-msix`. The workflow copies
the installed payload, excludes package footprint files, patches the selected
executable, and transforms its manifest for a new sparse identity.

For a package with multiple applications, pass `--source-application-id` to
select one. `--application-id` sets the new application ID. Framework, resource,
and optional packages are rejected. The source manifest and payload must be
readable. Dependencies are reported and remain separate from the copied layout.
Manifest transformation reports the entries it keeps or drops; check that report
for features the application needs.

All three workflows accept `--display-name`, `--application-id`,
`--overlay-manifest`, and `--overlay-files`. Overlay files are added to the
payload and must not collide with existing files.

## Activate, inspect status, and remove

Use the AUMID printed by registration, or use the package family name (PFN):

```powershell
& $repackager activate --aumid 'Example.Sparse_publisherid!Example' --arguments '--example'
& $repackager activate --package-family-name 'Example.Sparse_publisherid'
& $repackager status --name Example.Sparse
```

Replace the sample identifiers with the actual values. `activate` requires
exactly one of `--aumid` and `--package-family-name`. PFN activation starts the
first application declared in the installed package manifest. Use an AUMID to
select a specific application.

To remove registration:

```powershell
& $repackager unregister --name Example.Sparse
```

`unregister` also accepts `--aumid`, `--package-family-name`, or
`--package-full-name`. To remove a retrofit registration and its recorded files:

```powershell
& $repackager remove-retrofit --name Example.Sparse
```

The workflows store authoritative receipts under
`%LOCALAPPDATA%\Repackager\receipts`. Set `REPACKAGER_DATA_DIR` to change the data
root. `remove-retrofit --receipt FILE` can use an explicit receipt. Keep these
records for cleanup. Removal follows recorded paths, including created output
directories; keep user data outside generated layouts.

## Command reference

Use `repackager.exe help COMMAND` or `repackager.exe COMMAND --help` for syntax.

| Commands | Purpose |
| --- | --- |
| `list-win32 --directory DIR` | Find executables under a directory. |
| `list-msix` | List packages installed for the current user. |
| `inspect-exe`, `patch-exe-identity` | Read PE metadata or update embedded package identity. |
| `inspect-msix`, `extract-msix` | Inspect or extract package files. |
| `stage-files` | Copy application files into a staging directory. |
| `make-manifest` | Generate a `sparse_external` or `loose_full` manifest. |
| `transform-msix-manifest` | Transform a source manifest for a new sparse identity. |
| `apply-manifest-overlay` | Apply an XML overlay to a manifest. |
| `register-sparse`, `register-loose` | Register an existing layout. |
| `retrofit-win32-sparse`, `retrofit-win32-inplace`, `retrofit-msix-sparse` | Run a conversion workflow. |
| `activate`, `status`, `unregister`, `remove-retrofit` | Manage activation, status, registration, and cleanup. |
| `help`, `version` | Show usage or the build version. |

Operational commands accept `--report FILE` to write a text report in addition to
console output. `make-manifest` writes the manifest only; the caller must supply
the payload and referenced assets before registration.

| Exit code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Internal error |
| 2 | Usage error |
| 3 | Not found |
| 4 | Conflict |
| 5 | Validation error |
| 6 | Signature-loss consent required |
| 7 | Elevation error |
| 8 | Rolled back |
| 9 | Environment error |

## Current limitations

- Package identity changes can affect application behavior. Check activation,
  extensions, dependencies, and data paths with the converted application.
- PFN activation has a known path-encoding risk when the installation directory
  contains non-ASCII characters. The current implementation converts a Windows
  path through a narrow string before opening the manifest.
