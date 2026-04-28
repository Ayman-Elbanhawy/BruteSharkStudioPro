// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Beacon Detection Module
// Based on RITA's beacon detection algorithm (https://github.com/activecm/rita)
// Detects C2 callback patterns by analyzing connection timing,
// data sizes, and inter-arrival consistency.
// 
// A "beacon" is a periodic check-in from compromised hosts to a C2 server.
// Beacons typically have:
//   - Regular timing intervals (low jitter)
//   - Consistent data sizes
//   - Long connection durations (hours/days)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace PcapAnalyzer
{
    public class BeaconDetectionModule : IModule
    {
        public string Name => "C2 Beacon Detection";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // Minimum number of connections for a pair to be considered for beacon detection
        private const int MinConnections = 8;

        // Maximum jitter ratio allowed (lower = more regular)
        private const double MaxBeaconJitterRatio = 0.3;

        // Minimum data size similarity (0-1) for beacon candidates
        private const double MinDataSizeSimilarity = 0.60;

        // Track connection timestamps and data sizes per host-pair
        private readonly ConcurrentDictionary<string, List<ConnectionRecord>> _connections;

        public BeaconDetectionModule()
        {
            _connections = new ConcurrentDictionary<string, List<ConnectionRecord>>();
        }

        public void Analyze(TcpPacket tcpPacket)
        {
            RecordConnection(tcpPacket.SourceIp, tcpPacket.DestinationIp,
                tcpPacket.SourcePort, tcpPacket.DestinationPort,
                tcpPacket.Data?.Length ?? 0, "TCP");
        }

        public void Analyze(UdpPacket udpPacket)
        {
            RecordConnection(udpPacket.SourceIp, udpPacket.DestinationIp,
                udpPacket.SourcePort, udpPacket.DestinationPort,
                udpPacket.Data?.Length ?? 0, "UDP");
        }

        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        private void RecordConnection(string sourceIp, string destIp, int srcPort, int dstPort, int dataSize, string protocol)
        {
            // Use a bidirectional key so we catch both directions
            string key = string.Compare(sourceIp, destIp) < 0
                ? $"{sourceIp}<->{destIp}"
                : $"{destIp}<->{sourceIp}";

            var record = new ConnectionRecord
            {
                Timestamp = DateTime.UtcNow,
                SourceIp = sourceIp,
                DestinationIp = destIp,
                SourcePort = srcPort,
                DestinationPort = dstPort,
                DataSize = dataSize,
                Protocol = protocol
            };

            _connections.AddOrUpdate(key,
                _ => new List<ConnectionRecord> { record },
                (_, list) =>
                {
                    lock (list)
                    {
                        list.Add(record);
                        // Keep only the last 500 connections per pair
                        if (list.Count > 500) list.RemoveAt(0);
                    }
                    return list;
                });
        }

        /// <summary>
        /// Run beacon detection on all accumulated connections.
        /// Should be called after file processing completes.
        /// </summary>
        public void DetectBeacons()
        {
            foreach (var kvp in _connections)
            {
                string key = kvp.Key;
                List<ConnectionRecord> connections;

                lock (kvp.Value)
                {
                    if (kvp.Value.Count < MinConnections) continue;
                    connections = new List<ConnectionRecord>(kvp.Value);
                }

                var result = AnalyzeBeacon(connections, key);
                if (result != null)
                {
                    this.ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs()
                    {
                        ParsedItem = result
                    });
                }
            }
        }

        /// <summary>
        /// Analyze a set of connections for beacon-like behavior.
        /// Uses inter-arrival time analysis and data size similarity scoring.
        /// </summary>
        private BeaconResult AnalyzeBeacon(List<ConnectionRecord> connections, string pairKey)
        {
            try
            {
                // Sort by timestamp
                var sorted = connections.OrderBy(c => c.Timestamp).ToList();

                // Calculate inter-arrival times (in seconds)
                var iats = new List<double>();
                var dataSizes = new List<int>();

                for (int i = 1; i < sorted.Count; i++)
                {
                    double iat = (sorted[i].Timestamp - sorted[i - 1].Timestamp).TotalSeconds;
                    if (iat > 0 && iat < 86400) // Filter out gaps > 24h
                    {
                        iats.Add(iat);
                        dataSizes.Add(sorted[i].DataSize);
                    }
                }

                if (iats.Count < MinConnections - 1)
                    return null;

                // Calculate stats for inter-arrival times
                double meanIat = iats.Average();
                double stdIat = StandardDeviation(iats);
                double jitterRatio = meanIat > 0 ? stdIat / meanIat : 1.0;

                // Calculate data size similarity
                double dataSizeSimilarity = CalculateSizeSimilarity(dataSizes);

                // Calculate score (0-100)
                // Low jitter = high score, consistent sizes = high score
                double jitterScore = Math.Max(0, (1.0 - jitterRatio) * 60);
                double sizeScore = dataSizeSimilarity * 40;
                double totalScore = jitterScore + sizeScore;

                // Determine the likely beacon target (the external IP is the C2)
                var ips = pairKey.Split(new[] { "<->" }, StringSplitOptions.None);
                string probableC2 = DetermineProbableC2(sorted);

                // Only report high-confidence beacons
                if (totalScore >= 50 && jitterRatio <= MaxBeaconJitterRatio)
                {
                    return new BeaconResult
                    {
                        PairKey = pairKey,
                        ProbableC2Server = probableC2,
                        ConnectionCount = connections.Count,
                        MeanIntervalSeconds = meanIat,
                        JitterRatio = jitterRatio,
                        SizeSimilarity = dataSizeSimilarity,
                        BeaconScore = totalScore,
                        Protocol = sorted.First().Protocol,
                        DestinationPort = sorted.First().DestinationPort,
                        ObservationPeriod = sorted.Last().Timestamp - sorted.First().Timestamp
                    };
                }
            }
            catch { }

            return null;
        }

        private string DetermineProbableC2(List<ConnectionRecord> connections)
        {
            // Simple heuristic: the IP with more distinct connections is likely the C2
            var destIPs = connections.GroupBy(c => c.DestinationIp)
                .OrderByDescending(g => g.Count())
                .ToList();

            if (destIPs.Count >= 2)
            {
                // If one IP dominates, it's likely the C2
                if (destIPs[0].Count() > destIPs[1].Count() * 1.5)
                {
                    return destIPs[0].Key;
                }
            }

            // Fallback: the IP on the receiving end of most connections (higher port)
            var highPortConns = connections.Where(c => c.DestinationPort > 1024).ToList();
            if (highPortConns.Count > connections.Count * 0.7)
            {
                return highPortConns.First().DestinationIp;
            }

            return connections.First().DestinationIp;
        }

        private double StandardDeviation(List<double> values)
        {
            if (values.Count <= 1) return 0;
            double mean = values.Average();
            double sumSquaredDiffs = values.Sum(v => Math.Pow(v - mean, 2));
            return Math.Sqrt(sumSquaredDiffs / (values.Count - 1));
        }

        private double CalculateSizeSimilarity(List<int> sizes)
        {
            if (sizes.Count < 3) return 0;

            // Group sizes into buckets and check how many fall into the same bucket
            var sizeGroups = sizes.GroupBy(s =>
            {
                if (s == 0) return 0;
                // Bucket by order of magnitude (powers of 2)
                return (int)Math.Log(s, 2);
            }).OrderByDescending(g => g.Count()).ToList();

            if (sizeGroups.Count == 0) return 0;

            // Score based on how concentrated sizes are in the top buckets
            int topBucketCount = sizeGroups.Take(2).Sum(g => g.Count());
            return (double)topBucketCount / sizes.Count;
        }

        public void Clear()
        {
            _connections.Clear();
        }

        private class ConnectionRecord
        {
            public DateTime Timestamp { get; set; }
            public string SourceIp { get; set; }
            public string DestinationIp { get; set; }
            public int SourcePort { get; set; }
            public int DestinationPort { get; set; }
            public int DataSize { get; set; }
            public string Protocol { get; set; }
        }
    }

    public class BeaconResult : NetworkLayerObject
    {
        public string PairKey { get; set; }
        public string ProbableC2Server { get; set; }
        public int ConnectionCount { get; set; }
        public double MeanIntervalSeconds { get; set; }
        public double JitterRatio { get; set; }
        public double SizeSimilarity { get; set; }
        public double BeaconScore { get; set; }
        public new string Protocol { get; set; }
        public int DestinationPort { get; set; }
        public TimeSpan ObservationPeriod { get; set; }

        public override string ToString()
        {
            return $"Beacon: {PairKey} -> {ProbableC2Server}:{DestinationPort} " +
                   $"(Score: {BeaconScore:F0}%, Interval: {MeanIntervalSeconds:F1}s, " +
                   $"Jitter: {JitterRatio:P1}, Period: {ObservationPeriod.TotalHours:F1}h)";
        }
    }
}
