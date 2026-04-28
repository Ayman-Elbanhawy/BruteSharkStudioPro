// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Flow Aggregation & Statistics Engine for BruteShark Studio.
// NetFlow/IPFIX-style flow analysis with top talkers, protocol distribution,
// bandwidth usage, and connection statistics.
//
// Inspired by Zeek (Bro) conn.log format and flow analysis patterns.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace PcapAnalyzer
{
    /// <summary>
    /// Aggregated flow record representing a bidirectional communication flow.
    /// </summary>
    public class FlowRecord
    {
        public string SourceIp { get; set; }
        public string DestinationIp { get; set; }
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public string Protocol { get; set; }
        public string Service { get; set; }      // Detected application protocol
        public long TotalBytesSourceToDest { get; set; }
        public long TotalBytesDestToSource { get; set; }
        public long TotalBytes => TotalBytesSourceToDest + TotalBytesDestToSource;
        public int PacketCount { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public TimeSpan Duration => LastSeen - FirstSeen;

        // Flags (Zeek-style)
        public bool TcpHandshakeComplete { get; set; }
        public bool RstSeen { get; set; }
        public bool FinSeen { get; set; }
        public string ConnState { get; set; } // "S0","S1","SF","REJ","RSTO",etc.

        public string ServiceLabel => Service ?? $"{DestinationPort}/{Protocol?.ToUpper()}";
        public double BytesPerSecond => Duration.TotalSeconds > 0 ? TotalBytes / Duration.TotalSeconds : 0;

        public override string ToString()
            => $"{SourceIp}:{SourcePort} -> {DestinationIp}:{DestinationPort} [{ServiceLabel}] {FormatBytes(TotalBytes)}";

        public static string FormatBytes(long bytes)
        {
            if (bytes >= 1_073_741_824) return $"{bytes / 1_073_741_824.0:F1} GB";
            if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:F1} MB";
            if (bytes >= 1_024) return $"{bytes / 1_024.0:F1} KB";
            return $"{bytes} B";
        }
    }

    /// <summary>
    /// Flow aggregation engine that builds flow records from individual packets.
    /// Provides statistics: top talkers, protocol distribution, port usage, etc.
    /// </summary>
    public class FlowAggregationEngine : IModule
    {
        public string Name => "Flow Statistics & Aggregation";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        private readonly ConcurrentDictionary<string, FlowRecord> _flows;
        private readonly ConcurrentDictionary<string, HostStats> _hostStats;
        private readonly ConcurrentDictionary<int, int> _portHitCount;
        private readonly ConcurrentDictionary<string, long> _protocolBytes;
        private readonly object _statsLock = new object();

        private DateTime _analysisStart;
        private DateTime _analysisEnd;
        private long _totalBytesProcessed;
        private long _totalPacketsProcessed;

        public FlowAggregationEngine()
        {
            _flows = new ConcurrentDictionary<string, FlowRecord>();
            _hostStats = new ConcurrentDictionary<string, HostStats>();
            _portHitCount = new ConcurrentDictionary<int, int>();
            _protocolBytes = new ConcurrentDictionary<string, long>();
            _analysisStart = DateTime.MaxValue;
            _analysisEnd = DateTime.MinValue;
        }

        public void Analyze(TcpPacket tcpPacket)
        {
            RecordPacket(tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.SourcePort, tcpPacket.DestinationPort,
                "TCP", tcpPacket.Data?.Length ?? 0, out _);
        }

        public void Analyze(UdpPacket udpPacket)
        {
            RecordPacket(udpPacket.SourceIp, udpPacket.DestinationIp,
                udpPacket.SourcePort, udpPacket.DestinationPort,
                "UDP", udpPacket.Data?.Length ?? 0, out _);
        }

        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        private void RecordPacket(string src, string dst, int srcPort, int dstPort,
            string proto, int size, out FlowRecord flow)
        {
            flow = null;
            if (string.IsNullOrEmpty(src) || string.IsNullOrEmpty(dst)) return;

            Interlocked.Increment(ref _totalPacketsProcessed);
            Interlocked.Add(ref _totalBytesProcessed, size);

            var now = DateTime.UtcNow;

            // Update time range
            lock (_statsLock)
            {
                if (now < _analysisStart) _analysisStart = now;
                if (now > _analysisEnd) _analysisEnd = now;
            }

            // Use a deterministic flow key (lower IP:port first for bidirectional)
            string flowKey = BuildFlowKey(src, dst, srcPort, dstPort, proto);

            _flows.AddOrUpdate(flowKey,
                _ => CreateFlowRecord(src, dst, srcPort, dstPort, proto, size, now),
                (_, existing) =>
                {
                    lock (existing)
                    {
                        existing.PacketCount++;
                        if (src == existing.SourceIp)
                            existing.TotalBytesSourceToDest += size;
                        else
                            existing.TotalBytesDestToSource += size;
                        if (now < existing.FirstSeen) existing.FirstSeen = now;
                        if (now > existing.LastSeen) existing.LastSeen = now;
                    }
                    return existing;
                });

            // Update per-host statistics
            _hostStats.AddOrUpdate(src,
                _ => new HostStats { IpAddress = src, BytesSent = size, PacketsSent = 1, FirstSeen = now, LastSeen = now },
                (_, h) => { lock (h) { h.BytesSent += size; h.PacketsSent++; if (now > h.LastSeen) h.LastSeen = now; } return h; });

            _hostStats.AddOrUpdate(dst,
                _ => new HostStats { IpAddress = dst, BytesReceived = size, PacketsReceived = 1, FirstSeen = now, LastSeen = now },
                (_, h) => { lock (h) { h.BytesReceived += size; h.PacketsReceived++; if (now > h.LastSeen) h.LastSeen = now; } return h; });

            // Port hit counts
            _portHitCount.AddOrUpdate(dstPort, 1, (_, c) => c + 1);

            // Protocol bytes
            _protocolBytes.AddOrUpdate(proto, size, (_, b) => b + size);
        }

        private static string BuildFlowKey(string src, string dst, int sp, int dp, string proto)
        {
            // Consistent ordering for bidirectional flow key
            if (string.CompareOrdinal(src, dst) < 0 ||
                (src == dst && sp < dp))
                return $"{src}:{sp}-{dst}:{dp}-{proto}";
            return $"{dst}:{dp}-{src}:{sp}-{proto}";
        }

        private static FlowRecord CreateFlowRecord(string src, string dst, int sp, int dp,
            string proto, int size, DateTime now)
        {
            var fr = new FlowRecord
            {
                SourceIp = src, DestinationIp = dst,
                SourcePort = sp, DestinationPort = dp,
                Protocol = proto,
                TotalBytesSourceToDest = size,
                PacketCount = 1,
                FirstSeen = now, LastSeen = now,
                Service = ClassifyService(dp, proto)
            };

            // Mark connection state for TCP
            if (proto == "TCP") fr.ConnState = "OTH";
            return fr;
        }

        private static string ClassifyService(int port, string proto)
        {
            return (proto?.ToUpper(), port) switch
            {
                ("TCP", 80) or ("TCP", 8080) => "HTTP",
                ("TCP", 443) or ("TCP", 8443) => "HTTPS",
                ("TCP", 21) => "FTP",
                ("TCP", 22) => "SSH",
                ("TCP", 23) => "TELNET",
                ("TCP", 25) => "SMTP",
                ("TCP", 53) or ("UDP", 53) => "DNS",
                ("UDP", 67) or ("UDP", 68) => "DHCP",
                ("UDP", 69) => "TFTP",
                ("TCP", 110) => "POP3",
                ("TCP", 143) => "IMAP",
                ("UDP", 161) or ("UDP", 162) => "SNMP",
                ("TCP", 389) or ("TCP", 636) => "LDAP",
                ("TCP", 445) or ("TCP", 139) => "SMB",
                ("TCP", 1433) => "MSSQL",
                ("TCP", 3306) => "MySQL",
                ("TCP", 3389) => "RDP",
                ("TCP", 5432) => "PostgreSQL",
                ("TCP", 6379) => "Redis",
                ("TCP", 27017) => "MongoDB",
                ("UDP", 5060) or ("UDP", 5061) => "SIP",
                ("TCP", 6660) or ("TCP", 6667) or ("TCP", 6697) => "IRC",
                ("TCP", 4444) or ("TCP", 31337) or ("TCP", 1337) => "Suspicious",
                _ => $"{port}/{proto?.ToUpper()}"
            };
        }

        // === Statistics Queries ===

        public List<FlowRecord> GetTopFlows(int count = 20)
            => _flows.Values.OrderByDescending(f => f.TotalBytes).Take(count).ToList();

        public List<HostStats> GetTopTalkers(int count = 20)
            => _hostStats.Values.OrderByDescending(h => h.TotalBytes).Take(count).ToList();

        public List<KeyValuePair<int, int>> GetTopPorts(int count = 20)
            => _portHitCount.OrderByDescending(kv => kv.Value).Take(count).ToList();

        public Dictionary<string, long> GetProtocolDistribution()
            => _protocolBytes.ToDictionary(kv => kv.Key, kv => kv.Value);

        public FlowStatistics GetStatistics()
        {
            var flows = _flows.Values.ToList();
            return new FlowStatistics
            {
                TotalFlows = flows.Count,
                TotalPackets = _totalPacketsProcessed,
                TotalBytes = _totalBytesProcessed,
                UniqueSourceIps = new HashSet<string>(flows.Select(f => f.SourceIp)).Count,
                UniqueDestIps = new HashSet<string>(flows.Select(f => f.DestinationIp)).Count,
                UniquePorts = _portHitCount.Count,
                TcpFlows = flows.Count(f => f.Protocol == "TCP"),
                UdpFlows = flows.Count(f => f.Protocol == "UDP"),
                AvgBytesPerFlow = flows.Count > 0 ? _totalBytesProcessed / flows.Count : 0,
                AvgPacketsPerFlow = flows.Count > 0 ? (double)_totalPacketsProcessed / flows.Count : 0,
                TopProtocols = GetProtocolDistribution()
                    .OrderByDescending(kv => kv.Value).Take(5)
                    .ToDictionary(kv => kv.Key, kv => kv.Value),
                TopServices = flows.GroupBy(f => f.ServiceLabel)
                    .OrderByDescending(g => g.Count())
                    .Take(10)
                    .ToDictionary(g => g.Key, g => g.Count()),
                AnalysisDuration = _analysisEnd - _analysisStart,
                BytesPerSecond = (_analysisEnd - _analysisStart).TotalSeconds > 0
                    ? _totalBytesProcessed / (_analysisEnd - _analysisStart).TotalSeconds : 0
            };
        }

        public FlowRecord GetFlow(string flowKey)
        {
            _flows.TryGetValue(flowKey, out var flow);
            return flow;
        }

        public void Clear()
        {
            _flows.Clear();
            _hostStats.Clear();
            _portHitCount.Clear();
            _protocolBytes.Clear();
            _totalBytesProcessed = 0;
            _totalPacketsProcessed = 0;
            _analysisStart = DateTime.MaxValue;
            _analysisEnd = DateTime.MinValue;
        }
    }

    /// <summary>
    /// Per-host statistics record.
    /// </summary>
    public class HostStats
    {
        public string IpAddress { get; set; }
        public long BytesSent { get; set; }
        public long BytesReceived { get; set; }
        public long PacketsSent { get; set; }
        public long PacketsReceived { get; set; }
        public long TotalBytes => BytesSent + BytesReceived;
        public long TotalPackets => PacketsSent + PacketsReceived;
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }

        public override string ToString()
            => $"{IpAddress}  Sent: {FlowRecord.FormatBytes(BytesSent)}  Recv: {FlowRecord.FormatBytes(BytesReceived)}  Total: {FlowRecord.FormatBytes(TotalBytes)}";
    }

    /// <summary>
    /// Aggregate flow analysis statistics.
    /// </summary>
    public class FlowStatistics
    {
        public int TotalFlows { get; set; }
        public long TotalPackets { get; set; }
        public long TotalBytes { get; set; }
        public int UniqueSourceIps { get; set; }
        public int UniqueDestIps { get; set; }
        public int UniquePorts { get; set; }
        public int TcpFlows { get; set; }
        public int UdpFlows { get; set; }
        public long AvgBytesPerFlow { get; set; }
        public double AvgPacketsPerFlow { get; set; }
        public Dictionary<string, long> TopProtocols { get; set; } = new();
        public Dictionary<string, int> TopServices { get; set; } = new();
        public TimeSpan AnalysisDuration { get; set; }
        public double BytesPerSecond { get; set; }

        public override string ToString()
        {
            return $"Flows: {TotalFlows} ({TcpFlows} TCP, {UdpFlows} UDP) | " +
                   $"Packets: {TotalPackets:N0} | Data: {FlowRecord.FormatBytes(TotalBytes)} | " +
                   $"Hosts: {UniqueSourceIps} src / {UniqueDestIps} dst | " +
                   $"Ports: {UniquePorts} | " +
                   $"Rate: {FlowRecord.FormatBytes((long)BytesPerSecond)}/s | " +
                   $"Duration: {AnalysisDuration.TotalMinutes:F1}m";
        }
    }
}
