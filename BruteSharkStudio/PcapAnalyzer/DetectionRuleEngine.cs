// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Network Detection Rule Engine
// Inspired by YARA (VirusTotal) and Suricata rule systems.
// Provides a YARA-like rule engine for detecting patterns in network traffic
// including protocol-specific conditions, connection metadata, and payload matching.
//
// Rule format is JSON-based for easy authoring and sharing.
// Rules can match on: IPs, ports, protocols, payload hex/string patterns,
// connection metadata (timing, size), DNS queries, TLS metadata, and more.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    /// <summary>
    /// A detection rule for network traffic.
    /// </summary>
    public class NetworkDetectionRule
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public string Category { get; set; } // "C2", "Exfiltration", "Reconnaissance", "Malware", "Policy"
        public string Severity { get; set; } // "Low", "Medium", "High", "Critical"
        public string MitreTechnique { get; set; } // e.g., "T1071.001" (Application Layer Protocol: Web Protocols)

        // Connection-level conditions
        public List<string> SourceIps { get; set; } = new List<string>();
        public List<string> DestinationIps { get; set; } = new List<string>();
        public List<int> SourcePorts { get; set; } = new List<int>();
        public List<int> DestinationPorts { get; set; } = new List<int>();
        public List<string> Protocols { get; set; } = new List<string>();

        // Payload conditions (hex or ASCII)
        public List<string> PayloadHexPatterns { get; set; } = new List<string>();
        public List<string> PayloadStringPatterns { get; set; } = new List<string>();
        public bool PayloadMatchAll { get; set; } = true; // true = AND, false = OR

        // DNS conditions
        public List<string> DnsQueryPatterns { get; set; } = new List<string>();
        public int? MinDnsQueryLength { get; set; }
        public int? MaxDnsQueryLength { get; set; }

        // TLS/SSL conditions
        public List<string> Ja3Hashes { get; set; } = new List<string>();
        public List<string> TlsSniPatterns { get; set; } = new List<string>();

        // Metadata conditions
        public int? MinConnectionsPerMinute { get; set; }
        public int? MaxConnectionsPerMinute { get; set; }
        public int? MinPayloadSize { get; set; }
        public int? MaxPayloadSize { get; set; }

        // Time-based conditions
        public double? MaxJitterRatio { get; set; }
        public double? MinBeaconScore { get; set; }
    }

    /// <summary>
    /// Rule match result from the engine.
    /// </summary>
    public class RuleMatch
    {
        public string RuleName { get; set; }
        public string Description { get; set; }
        public string Category { get; set; }
        public string Severity { get; set; }
        public string MitreTechnique { get; set; }
        public string MatchDetails { get; set; }
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Detection Rule Engine for network traffic analysis.
    /// Evaluates packets, sessions, and DNS queries against a set of rules.
    /// </summary>
    public class DetectionRuleEngine
    {
        private readonly List<NetworkDetectionRule> _rules;
        private readonly List<RuleMatch> _matches;

        public IReadOnlyList<NetworkDetectionRule> Rules => _rules.AsReadOnly();
        public IReadOnlyList<RuleMatch> Matches => _matches.AsReadOnly();

        public event EventHandler<RuleMatchEventArgs> RuleMatched;

        public DetectionRuleEngine()
        {
            _rules = new List<NetworkDetectionRule>();
            _matches = new List<RuleMatch>();
            LoadDefaultRules();
        }

        /// <summary>
        /// Add a custom detection rule.
        /// </summary>
        public void AddRule(NetworkDetectionRule rule)
        {
            _rules.Add(rule);
        }

        /// <summary>
        /// Evaluate a TCP packet against all rules.
        /// </summary>
        public void EvaluatePacket(TcpPacket packet)
        {
            foreach (var rule in _rules)
            {
                var match = EvaluatePacketAgainstRule(packet, null, null, null, rule, "TCP");
                if (match != null)
                    RecordMatch(match);
            }
        }

        /// <summary>
        /// Evaluate a UDP packet against all rules.
        /// </summary>
        public void EvaluatePacket(UdpPacket packet)
        {
            foreach (var rule in _rules)
            {
                var match = EvaluatePacketAgainstRule(null, packet, null, null, rule, "UDP");
                if (match != null)
                    RecordMatch(match);
            }
        }

        /// <summary>
        /// Evaluate a DNS name mapping against all rules.
        /// </summary>
        public void EvaluateDns(DnsNameMapping dns)
        {
            foreach (var rule in _rules)
            {
                if (rule.DnsQueryPatterns == null || rule.DnsQueryPatterns.Count == 0)
                    continue;

                bool matched = rule.DnsQueryPatterns.Any(pattern =>
                {
                    try
                    {
                        return Regex.IsMatch(dns.Query, pattern, RegexOptions.IgnoreCase);
                    }
                    catch { return false; }
                });

                if (matched)
                {
                    RecordMatch(new RuleMatch
                    {
                        RuleName = rule.Name,
                        Description = rule.Description,
                        Category = rule.Category,
                        Severity = rule.Severity,
                        MitreTechnique = rule.MitreTechnique,
                        MatchDetails = $"DNS query matched pattern: {dns.Query} -> {dns.Destination}",
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
        }

        /// <summary>
        /// Evaluate a JA3 fingerprint against known-bad hashes.
        /// </summary>
        public void EvaluateJa3(Ja3Fingerprint fingerprint)
        {
            foreach (var rule in _rules)
            {
                if (rule.Ja3Hashes == null || rule.Ja3Hashes.Count == 0)
                    continue;

                if (rule.Ja3Hashes.Contains(fingerprint.Ja3Hash, StringComparer.OrdinalIgnoreCase))
                {
                    RecordMatch(new RuleMatch
                    {
                        RuleName = rule.Name,
                        Description = rule.Description,
                        Category = rule.Category,
                        Severity = rule.Severity,
                        MitreTechnique = rule.MitreTechnique,
                        SourceIp = fingerprint.SourceIp,
                        DestinationIp = fingerprint.DestinationIp,
                        DestinationPort = fingerprint.DestinationPort,
                        MatchDetails = $"Known malicious JA3: {fingerprint.Ja3Hash}",
                        Timestamp = DateTime.UtcNow
                    });
                }
            }
        }

        private RuleMatch EvaluatePacketAgainstRule(
            TcpPacket tcpPacket, UdpPacket udpPacket,
            TcpSession tcpSession, UdpStream udpStream,
            NetworkDetectionRule rule, string protocol)
        {
            string sourceIp = tcpPacket?.SourceIp ?? udpPacket?.SourceIp;
            string destIp = tcpPacket?.DestinationIp ?? udpPacket?.DestinationIp;
            int srcPort = tcpPacket?.SourcePort ?? udpPacket?.SourcePort ?? 0;
            int dstPort = tcpPacket?.DestinationPort ?? udpPacket?.DestinationPort ?? 0;
            byte[] data = tcpPacket?.Data ?? udpPacket?.Data;

            // Check IP filters
            if (rule.SourceIps.Count > 0 && !rule.SourceIps.Any(ip => MatchesIp(sourceIp, ip)))
                return null;
            if (rule.DestinationIps.Count > 0 && !rule.DestinationIps.Any(ip => MatchesIp(destIp, ip)))
                return null;

            // Check port filters
            if (rule.SourcePorts.Count > 0 && !rule.SourcePorts.Contains(srcPort))
                return null;
            if (rule.DestinationPorts.Count > 0 && !rule.DestinationPorts.Contains(dstPort))
                return null;

            // Check protocol filter
            if (rule.Protocols.Count > 0 && !rule.Protocols.Any(p => p.Equals(protocol, StringComparison.OrdinalIgnoreCase)))
                return null;

            // Check payload patterns
            if (data != null && data.Length > 0)
            {
                bool payloadMatch = false;

                // Check hex patterns
                if (rule.PayloadHexPatterns.Count > 0)
                {
                    foreach (var hexPattern in rule.PayloadHexPatterns)
                    {
                        byte[] patternBytes = Utilities.StringToByteArray(hexPattern);
                        if (Utilities.SearchForSubarray(data, patternBytes) >= 0)
                        {
                            payloadMatch = true;
                            break;
                        }
                    }
                }

                // Check string patterns
                if (!payloadMatch && rule.PayloadStringPatterns.Count > 0)
                {
                    foreach (var strPattern in rule.PayloadStringPatterns)
                    {
                        try
                        {
                            if (SearchInBytes(data, strPattern))
                            {
                                payloadMatch = true;
                                break;
                            }
                        }
                        catch { }
                    }
                }

                if ((rule.PayloadHexPatterns.Count > 0 || rule.PayloadStringPatterns.Count > 0) && !payloadMatch)
                    return null;
            }

            // Check payload size
            int payloadSize = data?.Length ?? 0;
            if (rule.MinPayloadSize.HasValue && payloadSize < rule.MinPayloadSize.Value)
                return null;
            if (rule.MaxPayloadSize.HasValue && payloadSize > rule.MaxPayloadSize.Value)
                return null;

            // All conditions matched
            return new RuleMatch
            {
                RuleName = rule.Name,
                Description = rule.Description,
                Category = rule.Category,
                Severity = rule.Severity,
                MitreTechnique = rule.MitreTechnique,
                SourceIp = sourceIp,
                DestinationIp = destIp,
                SourcePort = srcPort,
                DestinationPort = dstPort,
                MatchDetails = $"Rule '{rule.Name}' matched on {protocol} {sourceIp}:{srcPort} -> {destIp}:{dstPort}",
                Timestamp = DateTime.UtcNow
            };
        }

        private bool MatchesIp(string ip, string pattern)
        {
            if (ip == pattern) return true;
            if (pattern.Contains("/"))
            {
                // CIDR matching
                var parts = pattern.Split('/');
                if (parts.Length == 2 && int.TryParse(parts[1], out int cidr))
                {
                    try
                    {
                        byte[] ipBytes = System.Net.IPAddress.Parse(ip).GetAddressBytes();
                        byte[] netBytes = System.Net.IPAddress.Parse(parts[0]).GetAddressBytes();
                        int maskBits = cidr;
                        int fullBytes = maskBits / 8;
                        int remainingBits = maskBits % 8;

                        for (int i = 0; i < fullBytes; i++)
                        {
                            if (ipBytes[i] != netBytes[i]) return false;
                        }
                        if (remainingBits > 0 && fullBytes < ipBytes.Length)
                        {
                            int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                            if ((ipBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask))
                                return false;
                        }
                        return true;
                    }
                    catch { return false; }
                }
            }
            return false;
        }

        private bool SearchInBytes(byte[] data, string pattern)
        {
            byte[] patternBytes = Encoding.ASCII.GetBytes(pattern);
            return Utilities.SearchForSubarray(data, patternBytes) >= 0 ||
                   Utilities.SearchForSubarray(data, Encoding.UTF8.GetBytes(pattern)) >= 0;
        }

        private void RecordMatch(RuleMatch match)
        {
            _matches.Add(match);
            RuleMatched?.Invoke(this, new RuleMatchEventArgs { Match = match });
        }

        /// <summary>
        /// Load built-in default detection rules.
        /// These cover common C2 patterns, exfiltration, and reconnaissance.
        /// </summary>
        private void LoadDefaultRules()
        {
            // === C2 Detection Rules ===
            _rules.Add(new NetworkDetectionRule
            {
                Name = "SUSPICIOUS_DNS_TUNNELING",
                Description = "DNS query with unusually long subdomain (potential DNS tunneling/exfiltration)",
                Category = "Exfiltration",
                Severity = "High",
                MitreTechnique = "T1048.001",
                MinDnsQueryLength = 52,
                MaxDnsQueryLength = 255
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "C2_CALLBACK_KNOWN_PORTS",
                Description = "Outbound connection to common C2 ports (4444, 8080, 8443, 31337)",
                Category = "C2",
                Severity = "High",
                MitreTechnique = "T1571",
                DestinationPorts = new List<int> { 4444, 31337, 1337, 6666, 6667, 9999, 12345, 54321 }
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "SMB_EXFILTRATION",
                Description = "Large outbound SMB traffic (potential data exfiltration over SMB)",
                Category = "Exfiltration",
                Severity = "Medium",
                MitreTechnique = "T1048",
                DestinationPorts = new List<int> { 445, 139 },
                MinPayloadSize = 100000
            });

            // === Reconnaissance Rules ===
            _rules.Add(new NetworkDetectionRule
            {
                Name = "PORT_SCAN_VERTICAL",
                Description = "Multiple connections to different ports on same host (vertical port scan)",
                Category = "Reconnaissance",
                Severity = "Medium",
                MitreTechnique = "T1046",
                MinConnectionsPerMinute = 30
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "PORT_SCAN_HORIZONTAL",
                Description = "Same port probed across many hosts (horizontal scan)",
                Category = "Reconnaissance",
                Severity = "Medium",
                MitreTechnique = "T1046",
                MinConnectionsPerMinute = 50
            });

            // === Exfiltration Rules ===
            _rules.Add(new NetworkDetectionRule
            {
                Name = "DNS_EXFIL_LONG_TXT",
                Description = "Long DNS TXT record response (potential data exfiltration)",
                Category = "Exfiltration",
                Severity = "High",
                MitreTechnique = "T1048.001",
                DnsQueryPatterns = new List<string> { @"^[a-zA-Z0-9]{30,}\." }
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "ICMP_EXFILTRATION",
                Description = "Unusually large ICMP payload (potential ICMP tunneling)",
                Category = "Exfiltration",
                Severity = "Medium",
                MitreTechnique = "T1048.003",
                MinPayloadSize = 200
            });

            // === Malware Rules ===
            _rules.Add(new NetworkDetectionRule
            {
                Name = "MALWARE_EMOTET_JA3",
                Description = "TLS fingerprint matching known Emotet C2 infrastructure",
                Category = "Malware",
                Severity = "Critical",
                MitreTechnique = "T1571",
                Ja3Hashes = new List<string> { "72a25bd9663386c2ea4ba763feb9c690" }
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "MALWARE_TRICKBOT_JA3",
                Description = "TLS fingerprint matching known TrickBot C2",
                Category = "Malware",
                Severity = "Critical",
                MitreTechnique = "T1571",
                Ja3Hashes = new List<string> { "6734f37431670b3ab4292b8f60f29984" }
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "MALWARE_COBALT_STRIKE",
                Description = "TLS pattern matching Cobalt Strike default beacon",
                Category = "Malware",
                Severity = "Critical",
                MitreTechnique = "T1571",
                Ja3Hashes = new List<string> { "a0e9f5d64349fb13191b781eb81fd42e" }
            });

            // === Policy Violations ===
            _rules.Add(new NetworkDetectionRule
            {
                Name = "CLEARTEXT_FTP",
                Description = "Cleartext FTP authentication detected",
                Category = "Policy",
                Severity = "Low",
                MitreTechnique = "T1071.002",
                DestinationPorts = new List<int> { 21 },
                PayloadStringPatterns = new List<string> { "USER ", "PASS " }
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "CLEARTEXT_TELNET",
                Description = "Telnet traffic detected (cleartext credentials)",
                Category = "Policy",
                Severity = "Low",
                MitreTechnique = "T1071",
                DestinationPorts = new List<int> { 23 }
            });

            _rules.Add(new NetworkDetectionRule
            {
                Name = "SUSPICIOUS_POWERSHELL_WEB",
                Description = "PowerShell user-agent in HTTP (potential C2 staging)",
                Category = "C2",
                Severity = "Medium",
                MitreTechnique = "T1105",
                PayloadStringPatterns = new List<string>
                {
                    "WindowsPowerShell",
                    "PowerShell",
                    "Mozilla/5.0 (Windows NT; Windows NT"
                }
            });
        }
    }

    public class RuleMatchEventArgs : EventArgs
    {
        public RuleMatch Match { get; set; }
    }
}
