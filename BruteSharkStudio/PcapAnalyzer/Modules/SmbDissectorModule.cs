// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// SMB / DCE-RPC Protocol Dissector for BruteShark Studio.
// Extracts SMB authentication hashes (NTLMSSP over SMB), identifies
// named pipe connections (IPC$, browser, srvsvc, atsvc, etc.), and
// detects suspicious SMB activity (PSExec, WMI, schtasks).
//
// SMB Protocol (ports 445, 139):
//   SMBv1: NTLM in Session Setup AndX
//   SMBv2: NTLM in Session Setup Request
// DCE/RPC (over SMB named pipes): Remote procedure calls for lateral movement

using System;
using System.Collections.Generic;
using System.Text;

namespace PcapAnalyzer
{
    public class SmbDissectorModule : IModule
    {
        public string Name => "SMB / DCE-RPC Dissector";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        private static readonly byte[] Smb1Header = { 0xFF, 0x53, 0x4D, 0x42 }; // \xFFSMB
        private static readonly byte[] Smb2Header = { 0xFE, 0x53, 0x4D, 0x42 }; // \xFESMB
        private static readonly byte[] NtlmsspSig = { 0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00 };

        // Known SMB named pipes used for lateral movement
        private static readonly Dictionary<string, string> SuspiciousNamedPipes = new()
        {
            ["svcctl"] = "SCM Remote Service Control (SCManager)",
            ["atsvc"] = "Task Scheduler (schtasks / at)",
            ["samr"] = "SAM Remote Access (user enumeration)",
            ["lsarpc"] = "LSASS Remote (credential dumping)",
            ["browser"] = "Browser Protocol (network discovery)",
            ["wkssvc"] = "Workstation Service (share enumeration)",
            ["spoolss"] = "Print Spooler (printer exploitation)",
            ["netlogon"] = "NetLogon (domain auth)",
            ["srvsvc"] = "Server Service (share management)",
            ["epmapper"] = "Endpoint Mapper (DCOM)",
            ["winreg"] = "Remote Registry",
            ["ntsvcs"] = "NT Services",
            ["scerpc"] = "Security Configuration",
        };

        public void Analyze(UdpPacket udpPacket) { }
        public void Analyze(UdpStream udpStream) { }

        public void Analyze(TcpPacket tcpPacket)
        {
            ExtractSmbInfo(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.SourcePort, tcpPacket.DestinationPort);
        }

        public void Analyze(TcpSession tcpSession)
        {
            // Full session analysis for NTLM extraction
            ExtractSmbInfo(tcpSession.Data, tcpSession.SourceIp, tcpSession.DestinationIp,
                tcpSession.SourcePort, tcpSession.DestinationPort);
        }

        private void ExtractSmbInfo(byte[] data, string src, string dst, int sp, int dp)
        {
            if (data == null || data.Length < 10) return;

            // Check for SMB header
            bool isSmb1 = Utilities.SearchForSubarray(data, Smb1Header) >= 0;
            bool isSmb2 = Utilities.SearchForSubarray(data, Smb2Header) >= 0;

            if (!isSmb1 && !isSmb2) return;

            // Detect named pipe usage
            DetectNamedPipeAccess(data, src, dst, dp);

            // Extract NTLMSSP authentication
            ExtractSmbNtlm(data, src, dst, sp, dp);
        }

        private void DetectNamedPipeAccess(byte[] data, string src, string dst, int dp)
        {
            try
            {
                string text = Encoding.ASCII.GetString(data);

                foreach (var kvp in SuspiciousNamedPipes)
                {
                    if (text.Contains(kvp.Key))
                    {
                        EmitAlert("SMB Named Pipe", "MEDIUM",
                            $"SMB named pipe access: '{kvp.Key}' → {kvp.Value}. " +
                            $"From {src} to {dst}:{dp}."
                        );
                        break; // One alert per packet
                    }
                }
            }
            catch { }
        }

        private void ExtractSmbNtlm(byte[] data, string src, string dst, int sp, int dp)
        {
            int offset = 0;
            bool hasType2 = false;
            byte[] challenge = null;

            while (offset < data.Length - 12)
            {
                int sigPos = Utilities.SearchForSubarray(data, NtlmsspSig, offset);
                if (sigPos < 0) break;
                if (sigPos + 64 > data.Length) break;

                int msgType = BitConverter.ToInt32(data, sigPos + 8);

                if (msgType == 2) // Challenge
                {
                    challenge = new byte[8];
                    Array.Copy(data, sigPos + 24, challenge, 0, 8);
                    hasType2 = true;
                }
                else if (msgType == 3 && hasType2 && challenge != null) // Response
                {
                    int ntLen = BitConverter.ToUInt16(data, sigPos + 20);
                    int ntOff = BitConverter.ToUInt16(data, sigPos + 24);
                    int domLen = BitConverter.ToUInt16(data, sigPos + 28);
                    int domOff = BitConverter.ToUInt16(data, sigPos + 32);
                    int usrLen = BitConverter.ToUInt16(data, sigPos + 36);
                    int usrOff = BitConverter.ToUInt16(data, sigPos + 40);

                    if (usrLen <= 0 || ntLen <= 0) { offset = sigPos + 12; continue; }

                    string domain = SafeReadUnicode(data, sigPos + domOff,
                        Math.Min(domLen, data.Length - sigPos - domOff));
                    string user = SafeReadUnicode(data, sigPos + usrOff,
                        Math.Min(usrLen, data.Length - sigPos - usrOff));
                    string ntResp = SafeReadHex(data, sigPos + ntOff,
                        Math.Min(ntLen, data.Length - sigPos - ntOff));
                    string lmLen = BitConverter.ToUInt16(data, sigPos + 12).ToString();
                    string lmOff = BitConverter.ToUInt16(data, sigPos + 16).ToString();

                    string challengeHex = BitConverter.ToString(challenge).Replace("-", "").ToUpper();
                    string hashType = ntResp.Length > 48 ? "NTLMv2" : "NTLMv1";

                    EmitAlert("SMB NTLM Hash",
                        hashType == "NTLMv2" ? "HIGH" : "MEDIUM",
                        $"SMB authentication: {domain}\\{user} ({hashType}) | " +
                        $"{user}::{domain}:{challengeHex}:{ntResp.Substring(0, Math.Min(32, ntResp.Length))}"
                    );
                    break;
                }

                offset = sigPos + 12;
            }
        }

        private string SafeReadUnicode(byte[] data, int offset, int length)
        {
            if (offset < 0 || length <= 0 || offset + length > data.Length) return "";
            try { return Encoding.Unicode.GetString(data, offset, length).Replace("\0", ""); }
            catch { return ""; }
        }

        private string SafeReadHex(byte[] data, int offset, int length)
        {
            if (offset < 0 || length <= 0 || offset + length > data.Length) return "";
            try { return BitConverter.ToString(data, offset, length).Replace("-", ""); }
            catch { return ""; }
        }

        private void EmitAlert(string type, string severity, string details)
        {
            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = new PayloadAlert
                {
                    AlertType = type,
                    Severity = severity,
                    Details = details,
                    Protocol = "SMB",
                    Timestamp = DateTime.UtcNow
                }
            });
        }
    }
}
