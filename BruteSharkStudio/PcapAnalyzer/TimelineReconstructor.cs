// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Timeline Reconstruction Engine for BruteShark Studio.
// Merges events from ALL analysis modules into a single chronological timeline.
// Enables forensic investigators to see the complete picture of what happened
// on the network in the order it occurred.
//
// Events are tagged by source module, severity, and type for filtering.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PcapAnalyzer
{
    /// <summary>
    /// A single event in the forensic timeline.
    /// </summary>
    public class TimelineEvent : IComparable<TimelineEvent>
    {
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; }     // "Password", "Hash", "File", "DNS", "JA3", "Beacon", "Alert", "Connection"
        public string Source { get; set; }         // Source module: "Credentials", "DNS", "JA3", "Beacon", "Flow", "Payload"
        public string Severity { get; set; }       // "Info", "Low", "Medium", "High", "Critical"
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; }
        public string Summary { get; set; }        // Human-readable one-line summary
        public string Details { get; set; }        // Detailed technical information
        public object RawData { get; set; }        // Original parsed object for drill-down

        public int CompareTo(TimelineEvent other)
            => Timestamp.CompareTo(other?.Timestamp ?? DateTime.MinValue);

        public override string ToString()
            => $"{Timestamp:HH:mm:ss.fff} [{Severity}] {EventType}: {Summary} ({SourceIp} -> {DestinationIp})";
    }

    /// <summary>
    /// Timeline reconstruction engine that collects events from all modules
    /// and provides chronological querying and export capabilities.
    /// </summary>
    public class TimelineReconstructor : IDisposable
    {
        private readonly ConcurrentBag<TimelineEvent> _events;
        private readonly HashSet<string> _seenUniqueKeys;
        private readonly object _dedupLock = new object();
        private bool _disposed;

        public int EventCount => _events.Count;

        public TimelineReconstructor()
        {
            _events = new ConcurrentBag<TimelineEvent>();
            _seenUniqueKeys = new HashSet<string>();
        }

        /// <summary>
        /// Add a password credential event to the timeline.
        /// </summary>
        public void RecordPassword(NetworkPassword pw, DateTime? ts = null)
        {
            if (!TryDedup($"pw:{pw.Username}@{pw.Source}->{pw.Destination}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "Password",
                Source = "Credentials",
                Severity = "High",
                SourceIp = pw.Source,
                DestinationIp = pw.Destination,
                Protocol = pw.Protocol,
                Summary = $"Cleartext password: {pw.Username} ({pw.Protocol})",
                Details = $"Username: {pw.Username}\nPassword: {pw.Password}\nSource: {pw.Source} -> {pw.Destination}",
                RawData = pw
            });
        }

        /// <summary>
        /// Add a hash credential event to the timeline.
        /// </summary>
        public void RecordHash(NetworkHash hash, DateTime? ts = null)
        {
            string user = (hash is IDomainCredential dc) ? dc.GetUsername() : "";
            if (!TryDedup($"hash:{user}@{hash.Hash?.Substring(0, Math.Min(16, hash.Hash?.Length ?? 0))}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "Hash",
                Source = "Credentials",
                Severity = "Medium",
                SourceIp = hash.Source,
                DestinationIp = hash.Destination,
                Protocol = hash.Protocol,
                Summary = $"Auth hash: {user} ({hash.HashType})",
                Details = $"Type: {hash.HashType}\nHash: {hash.Hash}\nSource: {hash.Source} -> {hash.Destination}",
                RawData = hash
            });
        }

        /// <summary>
        /// Add a DNS event to the timeline.
        /// </summary>
        public void RecordDns(DnsNameMapping dns, DateTime? ts = null)
        {
            if (!TryDedup($"dns:{dns.Query}->{dns.Destination}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "DNS",
                Source = "DNS",
                Severity = "Info",
                Summary = $"DNS: {dns.Query} -> {dns.Destination}",
                Details = $"Query: {dns.Query}\nResolved: {dns.Destination}",
                RawData = dns
            });
        }

        /// <summary>
        /// Add a JA3 fingerprint event.
        /// </summary>
        public void RecordJa3(Ja3Fingerprint ja3, DateTime? ts = null)
        {
            if (!TryDedup($"ja3:{ja3.SourceIp}:{ja3.Ja3Hash}")) return;

            string severity = string.IsNullOrEmpty(ja3.KnownSoftware) ? "Info" : "Critical";
            string known = string.IsNullOrEmpty(ja3.KnownSoftware) ? "" : $" [{ja3.KnownSoftware}]";

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "TLS Fingerprint",
                Source = "JA3",
                Severity = severity,
                SourceIp = ja3.SourceIp,
                DestinationIp = ja3.DestinationIp,
                DestinationPort = ja3.DestinationPort,
                Summary = $"JA3: {ja3.Ja3Hash}{known}",
                Details = $"{ja3}",
                RawData = ja3
            });
        }

        /// <summary>
        /// Add a beacon detection event.
        /// </summary>
        public void RecordBeacon(BeaconResult beacon, DateTime? ts = null)
        {
            if (!TryDedup($"beacon:{beacon.PairKey}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "C2 Beacon",
                Source = "Beacon",
                Severity = beacon.BeaconScore >= 75 ? "Critical" : "High",
                DestinationIp = beacon.ProbableC2Server,
                DestinationPort = beacon.DestinationPort,
                Summary = $"C2 Beacon: {beacon.PairKey} (Score: {beacon.BeaconScore:F0}%)",
                Details = $"{beacon}",
                RawData = beacon
            });
        }

        /// <summary>
        /// Add a detection rule match.
        /// </summary>
        public void RecordRuleMatch(RuleMatch match, DateTime? ts = null)
        {
            if (!TryDedup($"rule:{match.RuleName}:{match.SourceIp}->{match.DestinationIp}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? match.Timestamp,
                EventType = "Rule Match",
                Source = "Rules",
                Severity = match.Severity,
                SourceIp = match.SourceIp,
                DestinationIp = match.DestinationIp,
                Summary = $"[{match.Category}] {match.RuleName}: {match.MatchDetails}",
                Details = $"Rule: {match.RuleName}\nCategory: {match.Category}\nMITRE: {match.MitreTechnique}",
                RawData = match
            });
        }

        /// <summary>
        /// Add a payload/shellcode alert.
        /// </summary>
        public void RecordPayloadAlert(PayloadAlert alert, DateTime? ts = null)
        {
            if (!TryDedup($"payload:{alert.AlertType}:{alert.SourceIp}:{alert.DestinationPort}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? alert.Timestamp,
                EventType = "Payload Alert",
                Source = "Payload",
                Severity = alert.Severity,
                SourceIp = alert.SourceIp,
                DestinationIp = alert.DestinationIp,
                SourcePort = alert.SourcePort,
                DestinationPort = alert.DestinationPort,
                Protocol = alert.Protocol,
                Summary = $"{alert.AlertType}: {alert.Details}",
                Details = alert.Details,
                RawData = alert
            });
        }

        /// <summary>
        /// Add a DNS exfiltration alert.
        /// </summary>
        public void RecordDnsExfilAlert(DnsExfilAlert alert, DateTime? ts = null)
        {
            if (!TryDedup($"dnsexfil:{alert.AlertType}:{alert.Query}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "DNS Exfiltration",
                Source = "DNS Exfil",
                Severity = alert.Severity,
                SourceIp = alert.SourceIp,
                DestinationIp = alert.DestinationIp,
                Summary = $"{alert.AlertType}: {alert.Query}",
                Details = alert.Details,
                RawData = alert
            });
        }

        /// <summary>
        /// Add a connection/first-seen event.
        /// </summary>
        public void RecordConnection(NetworkConnection conn, DateTime? ts = null)
        {
            if (!TryDedup($"conn:{conn.Source}:{conn.Destination}:{conn.Protocol}")) return;

            _events.Add(new TimelineEvent
            {
                Timestamp = ts ?? DateTime.UtcNow,
                EventType = "Connection",
                Source = "NetworkMap",
                Severity = "Info",
                SourceIp = conn.Source,
                DestinationIp = conn.Destination,
                SourcePort = conn.SrcPort,
                DestinationPort = conn.DestPort,
                Protocol = conn.Protocol,
                Summary = $"{conn.Protocol} {conn.Source}:{conn.SrcPort} -> {conn.Destination}:{conn.DestPort}",
                RawData = conn
            });
        }

        /// <summary>
        /// Generate chronological report as plain text.
        /// </summary>
        public string GenerateTextReport(int? maxEvents = null)
        {
            var sorted = GetChronological(maxEvents);
            var sb = new StringBuilder();

            sb.AppendLine("=== BruteShark Studio — Forensic Timeline Report ===");
            sb.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Total Events: {sorted.Count}");
            sb.AppendLine(new string('=', 70));

            string lastMinute = null;
            foreach (var evt in sorted)
            {
                string minute = evt.Timestamp.ToString("HH:mm");
                if (minute != lastMinute)
                {
                    sb.AppendLine($"\n--- {evt.Timestamp:HH:mm:ss} ---");
                    lastMinute = minute;
                }
                sb.AppendLine($"  [{evt.Severity,-8}] {evt.EventType,-15} {evt.Summary}");
            }

            sb.AppendLine($"\n=== End of Report ({sorted.Count} events) ===");
            return sb.ToString();
        }

        /// <summary>
        /// Get summary statistics by event type.
        /// </summary>
        public Dictionary<string, int> GetEventTypeCounts()
        {
            return _events.GroupBy(e => e.EventType)
                .ToDictionary(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// Get all events in chronological order.
        /// </summary>
        public List<TimelineEvent> GetChronological(int? maxEvents = null)
        {
            var sorted = _events.ToList();
            sorted.Sort();
            return maxEvents.HasValue ? sorted.Take(maxEvents.Value).ToList() : sorted;
        }

        /// <summary>
        /// Filter events by severity level.
        /// </summary>
        public List<TimelineEvent> FilterBySeverity(string minSeverity)
        {
            var severityOrder = new[] { "Info", "Low", "Medium", "High", "Critical" };
            int minIdx = Array.IndexOf(severityOrder, minSeverity);
            if (minIdx < 0) minIdx = 0;

            return GetChronological()
                .Where(e => Array.IndexOf(severityOrder, e.Severity) >= minIdx)
                .ToList();
        }

        /// <summary>
        /// Filter events involving a specific IP address.
        /// </summary>
        public List<TimelineEvent> FilterByIp(string ipAddress)
        {
            return GetChronological()
                .Where(e => e.SourceIp == ipAddress || e.DestinationIp == ipAddress)
                .ToList();
        }

        /// <summary>
        /// Clear all recorded events.
        /// </summary>
        public void Clear()
        {
            while (_events.TryTake(out _)) { }
            lock (_dedupLock) _seenUniqueKeys.Clear();
        }

        private bool TryDedup(string key)
        {
            lock (_dedupLock)
            {
                return _seenUniqueKeys.Add(key);
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Clear();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
