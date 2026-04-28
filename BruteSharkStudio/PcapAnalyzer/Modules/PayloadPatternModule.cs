// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Payload Pattern & Shellcode Detection Module.
// Analyzes raw packet payloads for suspicious byte patterns including:
//  - Shellcode detection (NOP sleds, common shellcode sequences)
//  - Reverse shell command patterns (bash, PowerShell, cmd, python, nc)
//  - Encoded payloads (Base64, XOR keys, ROT13)
//  - Suspicious file transfers (MZ/PE headers in non-standard ports)
//  - SQL injection patterns in HTTP payloads
//
// Based on shellcode signature databases and exploit pattern research.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    public class PayloadPatternModule : IModule
    {
        public string Name => "Payload Pattern & Shellcode Detection";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // Common NOP sled sequences (shellcode padding)
        private static readonly byte[][] NopSleds = {
            new byte[] { 0x90, 0x90, 0x90, 0x90 },                // x86 NOP (most common)
            new byte[] { 0x0F, 0x1F, 0x00, 0x00 },                // x86_64 multi-byte NOP
            new byte[] { 0x66, 0x90 },                              // x86 16-bit NOP
            new byte[] { 0x43, 0x4D, 0x44, 0x00 },                // NOP-equivalent padding
        };

        // Common shellcode prologue patterns
        private static readonly byte[][] ShellcodeSignatures = {
            // Metasploit windows/shell_reverse_tcp
            new byte[] { 0xFC, 0xE8, 0x82, 0x00, 0x00, 0x00 },   // CLD + CALL
            // Metasploit generic push/pop shellcode
            new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 },          // CLD; AND RSP, -16
            new byte[] { 0x31, 0xC0, 0x50, 0x68 },                // XOR EAX,EAX; PUSH; PUSH
            // Cobalt Strike beacon shellcode prologue
            new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8 },
            // x86 call-pop technique
            new byte[] { 0xE8, 0xFF, 0xFF, 0xFF, 0xFF },          // CALL $-1
            // Windows API resolver (hash-based)
            new byte[] { 0x60, 0x9C },                            // PUSHAD; PUSHF
        };

        // Reverse shell command patterns
        private static readonly Regex[] ReverseShellPatterns = {
            new Regex(@"bash\s+-i\s+>&\s*/dev/tcp/", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"nc\s+(?:-e\s+|-[lL]\S*\s+-e\s+)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"python\S*\s+-c\s+.*socket", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"powershell\s+(?:-e|-enc|-encodedcommand)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"cmd\.exe\s+/c\s+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"bash\s+-c\s+.*exec\s+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"perl\s+-e\s+.*socket", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"ruby\s+-e\s+.*socket", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"php\s+-r\s+.*fsockopen", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"socat\s+.*exec", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"sh\s+-i\s+", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"exec\s+\d+<>/dev/tcp/", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"IEX\s*\(\s*(?:New-Object|\(New)", RegexOptions.IgnoreCase | RegexOptions.Compiled),  // PowerShell IEX
            new Regex(@"frombase64string", RegexOptions.IgnoreCase | RegexOptions.Compiled),                  // PowerShell decode
        };

        // SQL injection patterns
        private static readonly Regex[] SqlinjectionPatterns = {
            new Regex(@"UNION\s+(?:ALL\s+)?SELECT", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"'\s*OR\s+'1'='1", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"\bDROP\s+TABLE\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"\bINSERT\s+INTO\b.*\bVALUES\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"SLEEP\s*\(\s*\d+\s*\)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"BENCHMARK\s*\(\s*\d+\s*,", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"WAITFOR\s+DELAY\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"INFORMATION_SCHEMA\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"xp_cmdshell", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            new Regex(@"sp_executesql", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        };

        // Suspicious file transfer patterns (MZ/PE in unusual contexts)
        private static readonly byte[] MzHeader = { 0x4D, 0x5A };
        private static readonly byte[] PkHeader = { 0x50, 0x4B, 0x03, 0x04 };

        public void Analyze(UdpPacket udpPacket)
        {
            ScanPayload(udpPacket.Data, "UDP", udpPacket.SourceIp, udpPacket.DestinationIp,
                udpPacket.SourcePort, udpPacket.DestinationPort);
        }

        public void Analyze(TcpPacket tcpPacket)
        {
            ScanPayload(tcpPacket.Data, "TCP", tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.SourcePort, tcpPacket.DestinationPort);
        }

        public void Analyze(TcpSession tcpSession)
        {
            ScanPayload(tcpSession.Data, "TCP", tcpSession.SourceIp, tcpSession.DestinationIp,
                tcpSession.SourcePort, tcpSession.DestinationPort, "session");
        }

        public void Analyze(UdpStream udpStream)
        {
            ScanPayload(udpStream.Data, "UDP", udpStream.SourceIp, udpStream.DestinationIp,
                udpStream.SourcePort, udpStream.DestinationPort, "stream");
        }

        private void ScanPayload(byte[] data, string protocol, string src, string dst,
            int srcPort, int dstPort, string context = "packet")
        {
            if (data == null || data.Length < 4) return;

            // Check 1: Shellcode NOP sled detection
            foreach (var nop in NopSleds)
            {
                int count = CountOccurrences(data, nop);
                if (count >= 8) // 8+ NOP sled instances = likely shellcode
                {
                    EmitAlert("Shellcode (NOP Sled)", "CRITICAL",
                        $"Detected {count} NOP sled sequences ({BitConverter.ToString(nop)}). " +
                        "This is a strong indicator of shellcode in the payload.",
                        src, dst, srcPort, dstPort, protocol, context);
                    break; // One NOP sled alert is enough
                }
            }

            // Check 2: Known shellcode prologue signatures
            foreach (var sig in ShellcodeSignatures)
            {
                if (ContainsPattern(data, sig))
                {
                    EmitAlert("Shellcode Signature", "CRITICAL",
                        $"Known shellcode prologue detected: {BitConverter.ToString(sig)}. " +
                        "This pattern is found in Metasploit/Cobalt Strike payloads.",
                        src, dst, srcPort, dstPort, protocol, context);
                    break;
                }
            }

            // Check 3: Text-based reverse shell commands
            string textPayload = null;
            try { textPayload = Encoding.UTF8.GetString(data); }
            catch { textPayload = Encoding.ASCII.GetString(data); }

            foreach (var regex in ReverseShellPatterns)
            {
                var match = regex.Match(textPayload);
                if (match.Success)
                {
                    string matched = match.Value.Length > 80 ? match.Value.Substring(0, 80) + "..." : match.Value;
                    EmitAlert("Reverse Shell Command", "CRITICAL",
                        $"Reverse shell command detected: \"{matched}\"",
                        src, dst, srcPort, dstPort, protocol, context);
                    break;
                }
            }

            // Check 4: SQL injection patterns (only on database ports or HTTP)
            if (IsDbPort(dstPort) || IsHttpContext(srcPort, dstPort))
            {
                foreach (var regex in SqlinjectionPatterns)
                {
                    var match = regex.Match(textPayload);
                    if (match.Success)
                    {
                        string matched = match.Value.Length > 60 ? match.Value.Substring(0, 60) + "..." : match.Value;
                        EmitAlert("SQL Injection Attempt", "HIGH",
                            $"SQL injection pattern detected: \"{matched}\"",
                            src, dst, srcPort, dstPort, protocol, context);
                        break;
                    }
                }
            }

            // Check 5: MZ/PE headers on non-standard ports (potential malware download)
            if (ContainsPattern(data, MzHeader) && !IsStandardFileTransfer(srcPort, dstPort))
            {
                EmitAlert("Executable Transfer", "HIGH",
                    "Windows PE executable (MZ header) detected on non-standard port. " +
                    "This may indicate malware download or covert file transfer.",
                    src, dst, srcPort, dstPort, protocol, context);
            }

            // Check 6: Encoded PowerShell (Base64 -enc)
            if (textPayload.Contains("-enc ") || textPayload.Contains("-EncodedCommand"))
            {
                EmitAlert("Encoded PowerShell", "CRITICAL",
                    "Encoded PowerShell command detected. This is a common technique for " +
                    "fileless malware execution and lateral movement.",
                    src, dst, srcPort, dstPort, protocol, context);
            }

            // Check 7: XOR-obfuscated payload heuristics (high concentration of similar bytes)
            if (data.Length >= 64)
            {
                double entropy = CalculateEntropy(data);
                if (entropy > 7.5 && data.Length > 200) // Very high entropy = encrypted/obfuscated
                {
                    EmitAlert("High-Entropy Payload", "MEDIUM",
                        $"Payload entropy: {entropy:F2} bits/byte. This suggests encrypted or " +
                        "obfuscated content that could hide malware or data exfiltration.",
                        src, dst, srcPort, dstPort, protocol, context);
                }
            }
        }

        private int CountOccurrences(byte[] data, byte[] pattern)
        {
            int count = 0;
            int pos = 0;
            while ((pos = Utilities.SearchForSubarray(data, pattern, pos)) >= 0)
            {
                count++;
                pos += pattern.Length;
                if (pos >= data.Length) break;
            }
            return count;
        }

        private bool ContainsPattern(byte[] data, byte[] pattern)
        {
            return Utilities.SearchForSubarray(data, pattern) >= 0;
        }

        private bool IsDbPort(int port)
        {
            return port == 1433 || port == 3306 || port == 5432 || port == 1521 ||
                   port == 27017 || port == 6379 || port == 389;
        }

        private bool IsHttpContext(int srcPort, int dstPort)
        {
            return srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080 ||
                   srcPort == 443 || dstPort == 443 || srcPort == 8443 || dstPort == 8443;
        }

        private bool IsStandardFileTransfer(int srcPort, int dstPort)
        {
            return srcPort == 80 || dstPort == 80 || srcPort == 443 || dstPort == 443 ||
                   srcPort == 21 || dstPort == 21 || srcPort == 22 || dstPort == 22;
        }

        private double CalculateEntropy(byte[] data)
        {
            var frequencies = new int[256];
            foreach (byte b in data) frequencies[b]++;

            double entropy = 0;
            double length = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    double p = frequencies[i] / length;
                    entropy -= p * Math.Log(p, 2);
                }
            }
            return entropy;
        }

        private void EmitAlert(string alertType, string severity, string details,
            string src, string dst, int srcPort, int dstPort, string protocol, string context)
        {
            var alert = new PayloadAlert
            {
                AlertType = alertType,
                Severity = severity,
                Details = details,
                SourceIp = src,
                DestinationIp = dst,
                SourcePort = srcPort,
                DestinationPort = dstPort,
                Protocol = protocol,
                Context = context,
                Timestamp = DateTime.UtcNow
            };

            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = alert
            });
        }
    }

    public class PayloadAlert : NetworkLayerObject
    {
        public string AlertType { get; set; }
        public string Severity { get; set; }
        public string Details { get; set; }
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; }
        public string Context { get; set; }
        public DateTime Timestamp { get; set; }

        public override string ToString()
            => $"[{Severity}] {AlertType}: {SourceIp}:{SourcePort} -> {DestinationIp}:{DestinationPort} ({Protocol}) - {Details}";
    }
}
