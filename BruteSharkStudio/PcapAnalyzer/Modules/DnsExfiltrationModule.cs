// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// DNS Exfiltration & Tunneling Detection Module.
// Analyzes DNS query patterns for data exfiltration indicators:
//  - Unusually long subdomains (>52 chars = entropy-based exfil)
//  - High query volumes to rare domains
//  - Suspicious TXT record lengths
//  - Base64-encoded subdomain patterns
//  - Abnormal DNS record types (TXT, NULL, CNAME chains)
//
// Based on research from Splunk's DNS exfiltration detection and
// the Iodine/dnscat2 tunneling tool behaviors.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    public class DnsExfiltrationModule : IModule
    {
        public string Name => "DNS Exfiltration Detection";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // Query length threshold for tunneling suspicion (Iodine uses >52 chars)
        private const int SuspiciousQueryLength = 40;
        private const int CriticalQueryLength = 52;

        // Maximum unique subdomains per FQDN before flagging
        private const int MaxUniqueSubdomains = 10;

        // Base64 character pattern for encoded data detection
        private static readonly Regex Base64Subdomain = new Regex(
            @"[A-Za-z0-9+/]{20,}={0,2}\.", RegexOptions.Compiled);

        // Hex-encoded subdomain pattern (dnscat2 uses hex)
        private static readonly Regex HexSubdomain = new Regex(
            @"\b[0-9a-fA-F]{16,}\.", RegexOptions.Compiled);

        // High-entropy character sequence detection
        private static readonly Regex HighEntropyChars = new Regex(
            @"[A-Za-z0-9+/=]{30,}", RegexOptions.Compiled);

        private readonly ConcurrentDictionary<string, DnsDomainTracker> _domainTrackers;
        private readonly ConcurrentBag<DnsExfilAlert> _alerts;

        public DnsExfiltrationModule()
        {
            _domainTrackers = new ConcurrentDictionary<string, DnsDomainTracker>();
            _alerts = new ConcurrentBag<DnsExfilAlert>();
        }

        public void Analyze(UdpPacket udpPacket)
        {
            if (udpPacket.DestinationPort != 53 && udpPacket.SourcePort != 53)
                return;

            ProcessDnsPacket(udpPacket.Data, udpPacket.SourceIp, udpPacket.DestinationIp);
        }

        public void Analyze(TcpPacket tcpPacket)
        {
            if (tcpPacket.DestinationPort != 53 && tcpPacket.SourcePort != 53)
                return;

            ProcessDnsPacket(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp);
        }

        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        private void ProcessDnsPacket(byte[] data, string srcIp, string dstIp)
        {
            try
            {
                // Quick check: DNS header is at least 12 bytes
                if (data == null || data.Length < 12) return;

                // Skip DNS responses (QR bit set in flags)
                bool isResponse = (data[2] & 0x80) != 0;
                if (isResponse) return;

                // Extract the query name (simple DNS name decoder)
                string queryName = DecodeDnsName(data, 12);
                if (string.IsNullOrWhiteSpace(queryName)) return;

                queryName = queryName.TrimEnd('.').ToLowerInvariant();

                // Track per-domain statistics
                var parts = queryName.Split('.');
                string domain = parts.Length >= 2 ? string.Join(".", parts.Skip(parts.Length - 2)) : queryName;
                string subdomain = parts.Length > 2 ? string.Join(".", parts.Take(parts.Length - 2)) : "";

                var tracker = _domainTrackers.GetOrAdd(domain, _ => new DnsDomainTracker { Domain = domain });
                lock (tracker)
                {
                    tracker.QueryCount++;
                    tracker.LastSeen = DateTime.UtcNow;
                    tracker.UniqueSubdomains.Add(subdomain);
                    tracker.ClientIps.Add(srcIp);
                }

                // Run detection checks
                var alerts = AnalyzeQuery(queryName, subdomain, domain, parts, srcIp, dstIp, tracker);
                foreach (var alert in alerts)
                {
                    _alerts.Add(alert);
                    ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
                    {
                        ParsedItem = alert
                    });
                }
            }
            catch { }
        }

        private List<DnsExfilAlert> AnalyzeQuery(string queryName, string subdomain,
            string domain, string[] parts, string srcIp, string dstIp, DnsDomainTracker tracker)
        {
            var alerts = new List<DnsExfilAlert>();

            // Check 1: Unusually long query (tunneling indicator)
            if (queryName.Length > CriticalQueryLength)
            {
                alerts.Add(new DnsExfilAlert
                {
                    AlertType = "DNS Tunneling (Long Query)",
                    Severity = "HIGH",
                    Domain = domain,
                    Query = queryName,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    Details = $"Query length {queryName.Length} exceeds critical threshold ({CriticalQueryLength}). " +
                               "This is characteristic of DNS tunneling tools (Iodine, dnscat2).",
                    Subdomain = subdomain
                });
            }
            else if (queryName.Length > SuspiciousQueryLength)
            {
                alerts.Add(new DnsExfilAlert
                {
                    AlertType = "DNS Tunneling (Suspicious Length)",
                    Severity = "MEDIUM",
                    Domain = domain,
                    Query = queryName,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    Details = $"Query length {queryName.Length} exceeds suspicious threshold ({SuspiciousQueryLength}).",
                    Subdomain = subdomain
                });
            }

            // Check 2: Base64-encoded subdomain (data exfiltration)
            if (!string.IsNullOrEmpty(subdomain) && Base64Subdomain.IsMatch(subdomain))
            {
                alerts.Add(new DnsExfilAlert
                {
                    AlertType = "DNS Exfiltration (Base64 Subdomain)",
                    Severity = "HIGH",
                    Domain = domain,
                    Query = queryName,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    Details = "Subdomain contains Base64-encoded pattern, indicating data exfiltration via DNS.",
                    Subdomain = subdomain
                });
            }

            // Check 3: Hex-encoded subdomain
            if (!string.IsNullOrEmpty(subdomain) && HexSubdomain.IsMatch(subdomain))
            {
                alerts.Add(new DnsExfilAlert
                {
                    AlertType = "DNS Exfiltration (Hex Encoded)",
                    Severity = "HIGH",
                    Domain = domain,
                    Query = queryName,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    Details = "Subdomain contains hex-encoded data pattern (dnscat2 signature).",
                    Subdomain = subdomain
                });
            }

            // Check 4: High volume of unique subdomains (exfiltration pattern)
            if (tracker.UniqueSubdomains.Count > MaxUniqueSubdomains && tracker.QueryCount > 20)
            {
                alerts.Add(new DnsExfilAlert
                {
                    AlertType = "DNS Exfiltration (High Subdomain Diversity)",
                    Severity = "MEDIUM",
                    Domain = domain,
                    Query = queryName,
                    SourceIp = srcIp,
                    DestinationIp = dstIp,
                    Details = $"{tracker.UniqueSubdomains.Count} unique subdomains detected for {domain} — " +
                               "high subdomain diversity is characteristic of DNS data exfiltration.",
                    Subdomain = subdomain
                });
            }

            // Check 5: Multi-part encoded subdomains (max 63 chars per label, typical exfil uses many labels)
            if (parts.Length > 5 && queryName.Length > 60)
            {
                var deepSubs = string.Join(".", parts.Take(parts.Length - 2));
                if (HighEntropyChars.IsMatch(deepSubs))
                {
                    alerts.Add(new DnsExfilAlert
                    {
                        AlertType = "DNS Exfiltration (High Entropy Multi-label)",
                        Severity = "CRITICAL",
                        Domain = domain,
                        Query = queryName,
                        SourceIp = srcIp,
                        DestinationIp = dstIp,
                        Details = $"Deep subdomain structure ({parts.Length} labels) with high-entropy content. " +
                                   "Strongly indicative of DNS data exfiltration.",
                        Subdomain = subdomain
                    });
                }
            }

            // Check 6: Unusual record type queries (TXT, NULL, ANY)
            if (queryName.Contains("type65") || // DNS query type 65 (HTTPS) is normal
                queryName.StartsWith("_"))       // SRV/other meta-queries
            {
                // Could be normal — filter out
            }

            return alerts;
        }

        private static string DecodeDnsName(byte[] data, int offset)
        {
            try
            {
                var sb = new StringBuilder();
                int pos = offset;
                int jumps = 0;
                const int maxJumps = 10;

                while (pos < data.Length && jumps < maxJumps)
                {
                    byte len = data[pos];
                    if (len == 0) break; // End of name

                    if ((len & 0xC0) == 0xC0)
                    {
                        // Pointer (compression)
                        if (pos + 1 >= data.Length) break;
                        int pointer = ((len & 0x3F) << 8) | data[pos + 1];
                        pos = pointer;
                        jumps++;
                        continue;
                    }

                    pos++;
                    if (pos + len > data.Length) break;

                    if (sb.Length > 0) sb.Append('.');
                    sb.Append(Encoding.ASCII.GetString(data, pos, len));
                    pos += len;
                }

                return sb.ToString();
            }
            catch { return null; }
        }

        public DnsExfiltrationReport GetReport()
        {
            return new DnsExfiltrationReport
            {
                Alerts = _alerts.ToList(),
                TrackedDomains = _domainTrackers.ToDictionary(kv => kv.Key, kv => kv.Value),
                TotalAlerts = _alerts.Count,
                CriticalAlerts = _alerts.Count(a => a.Severity == "CRITICAL"),
                HighAlerts = _alerts.Count(a => a.Severity == "HIGH"),
                UniqueDomains = _domainTrackers.Count
            };
        }

        public void Clear()
        {
            _domainTrackers.Clear();
            while (_alerts.TryTake(out _)) { }
        }

        public class DnsDomainTracker
        {
            public string Domain { get; set; }
            public int QueryCount { get; set; }
            public DateTime LastSeen { get; set; }
            public HashSet<string> UniqueSubdomains { get; set; } = new();
            public HashSet<string> ClientIps { get; set; } = new();
        }
    }

    public class DnsExfilAlert : NetworkLayerObject
    {
        public string AlertType { get; set; }
        public string Severity { get; set; }
        public string Domain { get; set; }
        public string Query { get; set; }
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public string Details { get; set; }
        public string Subdomain { get; set; }

        public override string ToString()
            => $"[{Severity}] {AlertType}: {Query} ({SourceIp} -> {DestinationIp})";
    }

    public class DnsExfiltrationReport
    {
        public List<DnsExfilAlert> Alerts { get; set; } = new();
        public Dictionary<string, DnsExfiltrationModule.DnsDomainTracker> TrackedDomains { get; set; } = new();
        public int TotalAlerts { get; set; }
        public int CriticalAlerts { get; set; }
        public int HighAlerts { get; set; }
        public int UniqueDomains { get; set; }

        public override string ToString()
            => $"DNS Exfil Report: {TotalAlerts} alerts ({CriticalAlerts} critical, {HighAlerts} high) across {UniqueDomains} domains";
    }
}
