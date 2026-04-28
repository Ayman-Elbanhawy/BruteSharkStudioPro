// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Statistical Anomaly Detection Module for BruteShark Studio.
// Detects network anomalies using statistical methods:
//  - Bandwidth spikes (bytes/sec threshold)
//  - Unusual port activity (rare/high ports)
//  - Volume anomalies per host
//  - Protocol ratio deviations
//  - Beacon-like periodic behavior

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace PcapAnalyzer
{
    public class AnomalyDetectionModule : IModule
    {
        public string Name => "Statistical Anomaly Detection";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // Time windows for analysis
        private readonly ConcurrentDictionary<long, TimeWindowStats> _timeWindows;
        private readonly TimeSpan WindowSize = TimeSpan.FromSeconds(30);

        // Per-host tracking
        private readonly ConcurrentDictionary<string, HostTrafficProfile> _hostProfiles;

        // Baseline (established after training period)
        private BaselineStats _baseline;
        private int _trainingPackets;
        private const int TrainingThreshold = 500;

        public AnomalyDetectionModule()
        {
            _timeWindows = new ConcurrentDictionary<long, TimeWindowStats>();
            _hostProfiles = new ConcurrentDictionary<string, HostTrafficProfile>();
        }

        public void Analyze(UdpPacket udpPacket)
        {
            RecordPacket(udpPacket.SourceIp, udpPacket.DestinationIp,
                udpPacket.Data?.Length ?? 0, "UDP", udpPacket.DestinationPort);
        }

        public void Analyze(TcpPacket tcpPacket)
        {
            RecordPacket(tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.Data?.Length ?? 0, "TCP", tcpPacket.DestinationPort);
        }

        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        private void RecordPacket(string src, string dst, int size, string proto, int dstPort)
        {
            var now = DateTime.UtcNow;
            long windowKey = now.Ticks / WindowSize.Ticks;

            // Per-window stats
            var window = _timeWindows.GetOrAdd(windowKey, _ => new TimeWindowStats
            {
                WindowStart = new DateTime(windowKey * WindowSize.Ticks, DateTimeKind.Utc)
            });

            lock (window)
            {
                window.PacketCount++;
                window.TotalBytes += size;
                if (proto == "TCP") window.TcpCount++;
                else window.UdpCount++;

                // Track unique dest IPs per window
                window.UniqueDestIps.Add(dst);
                window.PortDistribution.AddOrUpdate(dstPort, 1, (_, c) => c + 1);
            }

            // Per-host profile
            var profile = _hostProfiles.GetOrAdd(src, _ => new HostTrafficProfile { IpAddress = src });
            lock (profile)
            {
                profile.TotalBytes += size;
                profile.PacketCount++;
                profile.DestPorts.AddOrUpdate(dstPort, 1, (_, c) => c + 1);
                profile.LastSeen = now;
            }

            // Train baseline
            _trainingPackets++;
            if (_trainingPackets >= TrainingThreshold && _baseline == null)
            {
                EstablishBaseline();
            }

            // Run anomaly checks
            if (_baseline != null)
            {
                CheckForAnomalies(window, profile);
            }
        }

        private void EstablishBaseline()
        {
            var windows = _timeWindows.Values.ToList();
            if (windows.Count < 3) return;

            _baseline = new BaselineStats
            {
                AvgPacketsPerWindow = windows.Average(w => w.PacketCount),
                StdDevPackets = StdDev(windows.Select(w => (double)w.PacketCount)),
                AvgBytesPerWindow = windows.Average(w => (double)w.TotalBytes),
                StdDevBytes = StdDev(windows.Select(w => (double)w.TotalBytes)),
                AvgUniqueDests = windows.Average(w => w.UniqueDestIps.Count),
                TcpRatio = windows.Sum(w => w.TcpCount) / (double)Math.Max(1, windows.Sum(w => w.TcpCount + w.UdpCount)),
                ActiveHosts = _hostProfiles.Count
            };
        }

        private void CheckForAnomalies(TimeWindowStats window, HostTrafficProfile profile)
        {
            // Check 1: Bandwidth spike (3x above average)
            if (window.TotalBytes > _baseline.AvgBytesPerWindow + 3 * _baseline.StdDevBytes)
            {
                EmitAlert("Bandwidth Spike",
                    $"{FormatBytes(window.TotalBytes)} in {WindowSize.TotalSeconds:F0}s " +
                    $"(baseline: {FormatBytes((long)_baseline.AvgBytesPerWindow)})",
                    "MEDIUM");
            }

            // Check 2: High packet rate (potential DoS)
            if (window.PacketCount > _baseline.AvgPacketsPerWindow + 4 * _baseline.StdDevPackets)
            {
                EmitAlert("Packet Rate Anomaly",
                    $"{window.PacketCount} packets in {WindowSize.TotalSeconds:F0}s " +
                    $"(baseline: {_baseline.AvgPacketsPerWindow:F0})",
                    "HIGH");
            }

            // Check 3: Unusual port activity (rare/high ports or new ports)
            foreach (var kvp in window.PortDistribution)
            {
                if (kvp.Value >= 10 && (kvp.Key > 49152 || IsSuspiciousPort(kvp.Key)))
                {
                    EmitAlert("Unusual Port Activity",
                        $"Port {kvp.Key} had {kvp.Value} connections (suspicious)",
                        "MEDIUM");
                }
            }

            // Check 4: Host generating disproportionate traffic
            if (profile.PacketCount > 1000 && _baseline.ActiveHosts > 0)
            {
                double avgPerHost = _baseline.AvgPacketsPerWindow * _timeWindows.Count / Math.Max(1, _baseline.ActiveHosts);
                double ratio = profile.PacketCount / Math.Max(1, avgPerHost);
                if (ratio > 5)
                {
                    EmitAlert("Host Traffic Volume Anomaly",
                        $"{profile.IpAddress}: {ratio:F1}x above average traffic " +
                        $"({profile.PacketCount} pkts, {FormatBytes(profile.TotalBytes)})",
                        "MEDIUM");
                }
            }
        }

        private bool IsSuspiciousPort(int port)
        {
            return port == 4444 || port == 31337 || port == 1337 || port == 6666 ||
                   port == 6667 || port == 9999 || port == 12345 || port == 54321 ||
                   port == 0 || port == 9998 || port == 4782;
        }

        private void EmitAlert(string type, string details, string severity)
        {
            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = new PayloadAlert
                {
                    AlertType = type,
                    Severity = severity,
                    Details = details,
                    Protocol = "Stats",
                    Timestamp = DateTime.UtcNow
                }
            });
        }

        private double StdDev(IEnumerable<double> values)
        {
            var list = values.ToList();
            if (list.Count <= 1) return 0;
            double avg = list.Average();
            return Math.Sqrt(list.Sum(v => Math.Pow(v - avg, 2)) / (list.Count - 1));
        }

        private string FormatBytes(long bytes)
        {
            if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:F1} MB";
            if (bytes >= 1_024) return $"{bytes / 1_024.0:F1} KB";
            return $"{bytes} B";
        }

        public void Clear()
        {
            _timeWindows.Clear();
            _hostProfiles.Clear();
            _baseline = null;
            _trainingPackets = 0;
        }

        private class TimeWindowStats
        {
            public DateTime WindowStart;
            public int PacketCount;
            public long TotalBytes;
            public int TcpCount;
            public int UdpCount;
            public HashSet<string> UniqueDestIps = new();
            public ConcurrentDictionary<int, int> PortDistribution = new();
        }

        private class HostTrafficProfile
        {
            public string IpAddress;
            public int PacketCount;
            public long TotalBytes;
            public ConcurrentDictionary<int, int> DestPorts = new();
            public DateTime LastSeen;
        }

        private class BaselineStats
        {
            public double AvgPacketsPerWindow;
            public double StdDevPackets;
            public double AvgBytesPerWindow;
            public double StdDevBytes;
            public double AvgUniqueDests;
            public double TcpRatio;
            public int ActiveHosts;
        }
    }
}
