# BruteShark Desktop Studio v2.3.0

Professional network forensic analysis for Windows.

[![Version](https://img.shields.io/badge/version-2.3.0-blue)](https://github.com/Ayman-Elbanhawy/BruteSharkStudioPro/releases)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20x86-lightgrey)](https://github.com/Ayman-Elbanhawy/BruteSharkStudioPro)
[![License](https://img.shields.io/badge/license-GPL%20v3-green)](LICENSE)

BruteShark Desktop Studio helps investigators review packet captures, reconstruct sessions, extract credentials and hashes, detect suspicious traffic, fingerprint TLS/SSH activity, carve files, export evidence, and preserve analysis state from a polished WinForms desktop application.

Full help manual: [docs/BruteSharkStudioHelp.html](./docs/BruteSharkStudioHelp.html)

---

## Main Window

![BruteShark Desktop Studio main window](readme_media/BruteSharkDesktopStudio_Main_v2.png)

The v2.3 interface organizes the workflow into five areas:

| Area | Purpose |
| --- | --- |
| Files Analyzing | Add PCAP/PCAPNG files, remove files, and run offline analysis. |
| Modules | Enable or disable analysis modules before processing. |
| Options | Toggle TCP and UDP session reconstruction. |
| Actions | Export results or clear the current workspace. |
| Live Capture | Select an interface, apply a BPF filter, enable promiscuous mode, and start or stop live capture. |

The lower toolbar provides quick access to `+ Add`, `Run`, `Export`, `Clear`, `Save`, `Open`, `PDF`, `?` Help, and the moon/sun theme toggle. The left navigation tree contains all result views and now remains fully visible with vertical scrolling.

---

## Download

| Package | Path |
| --- | --- |
| MSI installer | [release/BruteSharkDesktopStudioInstaller.msi](./release/BruteSharkDesktopStudioInstaller.msi) |
| ZIP package | [release/BruteSharkDesktopStudioInstaller.zip](./release/BruteSharkDesktopStudioInstaller.zip) |

The installer bundles the desktop app, required DLLs, the HTML help manual, the main screenshot, README documentation, and Hashcat v7.1.2.

---

## Quick Start

1. Install BruteShark Desktop Studio from the MSI.
2. Start the application from the desktop or Start menu shortcut.
3. Click `+ Add` and select one or more `.pcap`, `.pcapng`, or `.cap` files.
4. Keep TCP/UDP session reconstruction enabled for the deepest analysis.
5. Select the modules you want in the `Modules` checklist.
6. Click `Run` or `Analyze`.
7. Browse results from the left navigation tree.
8. Click `Export` to generate evidence files and a full HTML forensic report.
9. Click `Save` to preserve the case as a `.bsproj` file.

For live capture, select a network interface, optionally enter a BPF filter such as `tcp port 80` or `host 192.168.1.10`, choose promiscuous mode if needed, and click `Start`.

---

## Result Views

| View | What it Shows |
| --- | --- |
| Credentials > Passwords | Extracted cleartext credentials. |
| Credentials > Hashes | NTLM, Kerberos, HTTP Digest, CRAM-MD5, POP3 APOP, and other authentication hashes. |
| Network > Network Map | Host relationships and observed connections. |
| Network > Sessions | Reconstructed TCP/UDP sessions. |
| Network > DNS | DNS mappings and query/response activity. |
| Data > Files | Carved files reconstructed from network streams. |
| Data > VoIP Calls | SIP/RTP call metadata and media artifacts. |
| Detection & Alerts | Payload alerts, C2 beacon candidates, and detection rule matches. |
| Fingerprints & TLS | JA3/JA3S, TLS certificates, and SSH fingerprints. |
| Protocol Analysis | HTTP, SMB, DHCP, and ARP protocol findings. |
| Anomalies | Statistical anomalies and unusual traffic patterns. |
| Exfiltration | DNS exfiltration indicators. |
| Tools | Packet hex viewer. |
| Statistics | Protocol statistics and traffic summaries. |
| Timeline | Chronological event timeline. |
| Flow Statistics | NetFlow-style flow summaries. |
| BACnet Analysis | BACnet diagnostics and health indicators. |
| Monitor | Capture comparison and preview monitoring nodes. |
| Audit Log | Timestamped application activity trail. |

---

## Analysis Capabilities

### Credentials and Hashes

- NTLMv1/NTLMv2 from SMB, HTTP NTLM, LDAP, and RDP NLA.
- Kerberos AS-REQ, AS-REP, and TGS-REP material.
- HTTP Basic and Digest authentication.
- FTP, SMTP, IMAP, POP3, VNC, SNMP, IRC, LDAP, and CRAM-MD5 credentials where present in capture data.
- Hashcat-ready export grouped by hash type.

### Network Reconstruction

- TCP and UDP session reconstruction.
- Network endpoint mapping.
- DNS mapping and query tracking.
- VoIP/SIP/RTP call extraction.
- File carving from network streams.

### Detection and Fingerprinting

- C2 beacon detection.
- Detection rule matching.
- Payload pattern alerts.
- DNS exfiltration indicators.
- ARP spoofing and DHCP snooping.
- HTTP metadata extraction.
- SMB activity analysis.
- TLS certificate extraction and suspicious certificate flags.
- JA3/JA3S and SSH fingerprinting.
- Statistical anomaly detection.

### Case Management and Usability

- Save and open `.bsproj` project files.
- Dark/light theme toggle.
- Help/manual button in the main toolbar.
- Tooltips for primary buttons and navigation items.
- Vertical and horizontal scrolling for large navigation trees and result tables.
- Audit log for key user actions.

---

## Export Outputs

Click `Export` and choose an output folder. BruteShark creates evidence artifacts for the data available in the current case, including:

- Carved files.
- Network map data.
- VoIP call data.
- Network node data.
- DNS mappings.
- JA3/JA3S fingerprints.
- Beacon results.
- Detection rule matches.
- SSH fingerprints.
- DHCP leases.
- HTTP transactions.
- Payload alerts.
- TLS certificates.
- DNS exfiltration alerts.
- Hashcat-ready hash files.
- Full interactive HTML forensic report.

The `PDF` toolbar button creates a PDF-ready HTML report. Open the generated report in a browser and use `Print` -> `Save as PDF` when a PDF file is required.

---

## Hashcat Workflow

The installer includes Hashcat v7.1.2 and adds the Hashcat folder to the system PATH during elevated installation.

1. Analyze one or more captures.
2. Open `Credentials > Hashes`.
3. Select a hash type.
4. Choose an output directory and wordlist.
5. Optionally add extra Hashcat arguments, such as a rules file.
6. Click `Create Hashcat file` or `Crack with Hashcat`.

Common hash modes include:

| Hash Type | Hashcat Mode |
| --- | --- |
| NTLMv1 | 5500 |
| NTLMv2 | 5600 |
| Kerberos AS-REQ RC4 | 7500 |
| Kerberos AS-REP RC4 | 18200 |
| Kerberos TGS-REP RC4 | 13100 |
| Kerberos TGS-REP AES128 | 19600 |
| Kerberos TGS-REP AES256 | 19700 |
| HTTP Digest MD5 | 11400 |
| CRAM-MD5 | 16400 |
| POP3 APOP | 9900 |

---

## Keyboard Shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+S` | Save project as `.bsproj`. |
| `Ctrl+O` | Open a saved project. |
| `Ctrl+P` | Export a PDF-ready HTML report. |

---

## Live Capture Notes

Live capture requires a compatible packet capture driver such as Npcap. For best results:

- Run the application with appropriate privileges when capturing from protected interfaces.
- Use BPF filters to reduce noise during capture.
- Enable promiscuous mode only when you need to observe traffic not addressed to the local host.
- Stop capture before exporting if you want a stable snapshot of the current case.

---

## Build from Source

Requirements:

- Windows.
- .NET 8 SDK.
- WiX Toolset 3.11 files under `BruteSharkStudio\packages\WiX.3.11.2\tools`.
- Hashcat staged under `BruteSharkStudio\BruteSharkDesktopInstaller\Assets\Hashcat`.

Build the desktop app:

```powershell
cd C:\WireSharkTools\BruteSharkPro\BruteSharkStudio\BruteSharkDesktop
dotnet build .\BruteSharkDesktop.csproj
```

Build the MSI:

```powershell
cd C:\WireSharkTools\BruteSharkPro\BruteSharkStudio\BruteSharkDesktopInstaller
dotnet msbuild .\BruteSharkDesktopInstaller.wixproj /p:Configuration=Debug /p:Platform=x86
```

The MSI is generated at:

```text
BruteSharkStudio\BruteSharkDesktopInstaller\bin\Debug\BruteSharkDesktopStudioInstaller.msi
```

Release copies are stored in:

```text
release\BruteSharkDesktopStudioInstaller.msi
release\BruteSharkDesktopStudioInstaller.zip
```

---

## Responsible Use

BruteShark Desktop Studio is intended for authorized security monitoring, incident response, lab analysis, and forensic investigations. Only analyze captures you are authorized to inspect.

---

## License

GPL v3. See [LICENSE](./LICENSE).
