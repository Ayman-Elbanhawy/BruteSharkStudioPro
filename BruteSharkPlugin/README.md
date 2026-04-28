# BruteShark Studio Wireshark Plugin

This folder contains a Wireshark Lua plugin that integrates BruteShark Studio with Wireshark by running `BruteSharkDesktopStudioCli.exe` against capture files that you load through the BruteShark menu.

Wireshark cannot load the BruteShark .NET WinForms desktop application or its .NET assemblies as a native in-process plugin. This plugin is therefore an out-of-process bridge:

1. Use `Tools > BruteShark > Load capture files or folder...` and select `.pcap` / `.pcapng` files or a folder containing captures.
2. The Lua plugin stores those paths for the current Wireshark session.
3. BruteShark Studio runs the selected modules against the loaded files.
4. Results are printed in a Wireshark text window and exported to an output directory.

## Prerequisites

- Wireshark with Lua enabled.
- BruteShark Studio CLI built locally.
- The default plugin path expects:

```text
C:\SourceCode\WireSharkTools\BruteSharkStudio\BruteSharkStudio\BruteSharkCli\bin\Debug\net8.0\BruteSharkDesktopStudioCli.exe
```

Build it with:

```powershell
$env:DOTNET_CLI_HOME='C:\SourceCode\WireSharkTools\BruteSharkStudio\.dotnet-home'
dotnet build 'C:\SourceCode\WireSharkTools\BruteSharkStudio\BruteSharkStudio\BruteSharkCli\BruteSharkCli.csproj' -v:minimal
```

## Install

Run:

```powershell
powershell -ExecutionPolicy Bypass -File 'C:\SourceCode\WireSharkTools\BruteSharkStudio\BruteSharkPlugin\install.ps1'
```

Then restart Wireshark.

## Use

Load one or more capture files first:

- `Tools > BruteShark > Load capture files or folder...`

The plugin opens a Windows file picker first. Select one or more capture files, or cancel if you only want to choose a folder. It then opens a folder picker; select a folder to recursively add `.pcap` / `.pcapng` files from that folder, or cancel to skip folders.

You can also load paths manually:

- `Tools > BruteShark > Load capture paths manually...`

For manual loading, enter one or more `.pcap` / `.pcapng` paths separated by semicolons:

```text
C:\captures\one.pcap;C:\captures\two.pcapng
```

Then use:

- `Tools > BruteShark > Analyze loaded capture files`
- `Tools > BruteShark > Extract credentials and hashes`
- `Tools > BruteShark > Build network map and DNS`
- `Tools > BruteShark > Show loaded capture files`
- `Tools > BruteShark > Clear loaded capture files`
- `Tools > BruteShark > Configure and run...`

The default output directory is:

```text
%TEMP%\BruteSharkWireshark
```

Use `Configure and run...` to set a different CLI path, module list, capture path, or output directory.

## Supported BruteShark modules

The plugin passes these module names to `BruteSharkDesktopStudioCli.exe`:

- `Credentials`
- `FileExtracting`
- `NetworkMap`
- `DNS`
- `Voip`

The `Credentials` module includes password and hash extraction.
