using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CommonUi
{
    public class NetworkContext
    {
        private enum SessionsType
        {
            TCP,
            UDP
        };

        public Dictionary<string, HashSet<int>> OpenPorts { get; private set; }
        public HashSet<PcapAnalyzer.DnsNameMapping> DnsMappings { get; private set; }
        public HashSet<PcapAnalyzer.NetworkHash> Hashes { get; private set; }
        public HashSet<PcapAnalyzer.NetworkConnection> Connections { get; private set; }
        public HashSet<PcapProcessor.INetworkSession<PcapProcessor.NetworkPacket>> NetworkSessions { get; private set; }

        // Phase 2+ additions: JA3 fingerprinting and beacon/rule detection
        public List<PcapAnalyzer.Ja3Fingerprint> Ja3Fingerprints { get; private set; }
        public List<PcapAnalyzer.BeaconResult> BeaconResults { get; private set; }
        public List<PcapAnalyzer.RuleMatch> DetectionMatches { get; private set; }

        public int Ja3Count => Ja3Fingerprints.Count;
        public int BeaconCount => BeaconResults.Count;
        public List<PcapAnalyzer.SshServerFingerprint> SshFingerprints { get; private set; }
        public List<PcapAnalyzer.DhcpLease> DhcpLeases { get; private set; }
        public List<PcapAnalyzer.HttpTransaction> HttpTransactions { get; private set; }
        public List<PcapAnalyzer.PayloadAlert> PayloadAlerts { get; private set; }
        public List<PcapAnalyzer.TlsCertificate> TlsCertificates { get; private set; }
        public List<PcapAnalyzer.NetworkPassword> Passwords { get; private set; }
        public List<PcapAnalyzer.NetworkFile> NetworkFiles { get; private set; }
        public HashSet<PcapAnalyzer.VoipCall> VoipCalls { get; private set; }

        public NetworkContext()
        {
            OpenPorts = new Dictionary<string, HashSet<int>>();
            DnsMappings = new HashSet<PcapAnalyzer.DnsNameMapping>();
            Hashes = new HashSet<PcapAnalyzer.NetworkHash>();
            Connections = new HashSet<PcapAnalyzer.NetworkConnection>();
            NetworkSessions = new HashSet<PcapProcessor.INetworkSession<PcapProcessor.NetworkPacket>>();
            Ja3Fingerprints = new List<PcapAnalyzer.Ja3Fingerprint>();
            BeaconResults = new List<PcapAnalyzer.BeaconResult>();
            DetectionMatches = new List<PcapAnalyzer.RuleMatch>();
            SshFingerprints = new List<PcapAnalyzer.SshServerFingerprint>();
            DhcpLeases = new List<PcapAnalyzer.DhcpLease>();
            HttpTransactions = new List<PcapAnalyzer.HttpTransaction>();
            PayloadAlerts = new List<PcapAnalyzer.PayloadAlert>();
            TlsCertificates = new List<PcapAnalyzer.TlsCertificate>();
            Passwords = new List<PcapAnalyzer.NetworkPassword>();
            NetworkFiles = new List<PcapAnalyzer.NetworkFile>();
            VoipCalls = new HashSet<PcapAnalyzer.VoipCall>();
        }

        public void HandleJa3Fingerprint(PcapAnalyzer.Ja3Fingerprint fingerprint)
        {
            Ja3Fingerprints.Add(fingerprint);
        }

        public void AddBeaconResult(PcapAnalyzer.BeaconResult beacon)
        {
            BeaconResults.Add(beacon);
        }

        public void AddDetectionMatch(PcapAnalyzer.RuleMatch match)
        {
            DetectionMatches.Add(match);
        }

        public bool HandleDnsNameMapping(PcapAnalyzer.DnsNameMapping dnsNameMapping)
        {
            return DnsMappings.Add(dnsNameMapping);
        }

        public void AddPassword(PcapAnalyzer.NetworkPassword password)
        {
            Passwords.Add(password);
        }

        public void AddNetworkFile(PcapAnalyzer.NetworkFile file)
        {
            NetworkFiles.Add(file);
        }

        public void AddVoipCall(PcapAnalyzer.VoipCall call)
        {
            VoipCalls.Add(call);
        }

        public void AddSshFingerprint(PcapAnalyzer.SshServerFingerprint fingerprint)
        {
            SshFingerprints.Add(fingerprint);
        }

        public void AddDhcpLease(PcapAnalyzer.DhcpLease lease)
        {
            DhcpLeases.Add(lease);
        }

        public void AddHttpTransaction(PcapAnalyzer.HttpTransaction transaction)
        {
            HttpTransactions.Add(transaction);
        }

        public void AddPayloadAlert(PcapAnalyzer.PayloadAlert alert)
        {
            PayloadAlerts.Add(alert);
        }

        public void AddTlsCertificate(PcapAnalyzer.TlsCertificate cert)
        {
            TlsCertificates.Add(cert);
        }

        public void HandleNetworkConection(PcapAnalyzer.NetworkConnection networkConnection)
        {
            // Create network nodes if needed.
            if (Connections.Add(networkConnection))
            {
                if (!OpenPorts.ContainsKey(networkConnection.Source))
                {
                    OpenPorts[networkConnection.Source] = new HashSet<int>();
                }
                if (!OpenPorts.ContainsKey(networkConnection.Destination))
                {
                    OpenPorts[networkConnection.Destination] = new HashSet<int>();
                }
            }

            // Update open ports.
            OpenPorts[networkConnection.Source].Add(networkConnection.SrcPort);
            OpenPorts[networkConnection.Destination].Add(networkConnection.DestPort);
        }

        private NetworkNode GetNode(string ipAddress)
        {
            var tcpSessionsCount = 0;
            var udpSessionsCount = 0;
            var sentData = 0;
            var receivedData = 0;
            var domains = new HashSet<string>();
            var domainUsers = new HashSet<string>();

            // We iterate all the session once and calculate various things at 
            // once (sessions count, data sent etc..)
            foreach (var session in this.NetworkSessions
                .Where(s => s.SourceIp == ipAddress || s.DestinationIp == ipAddress))
            {
                if (session.Protocol == "TCP")
                    tcpSessionsCount++;
                else if (session.Protocol == "UDP")
                    udpSessionsCount++;

                if (session.SourceIp == ipAddress)
                {
                    sentData += session.SentData;
                    receivedData += session.ReceivedData;
                }
                else
                {
                    sentData += session.ReceivedData;
                    receivedData += session.SentData;
                }
            }

            foreach (var hash in this.Hashes.Where(h => h.Destination == ipAddress))
            {
                if (hash is PcapAnalyzer.IDomainCredential)
                {
                    var domainHash = hash as PcapAnalyzer.IDomainCredential;
                    var domain = domainHash.GetDoamin();
                    var user = domainHash.GetUsername();

                    if (!string.IsNullOrWhiteSpace(domain))
                        domains.Add(domain);
                    if (!string.IsNullOrWhiteSpace(user))
                        domainUsers.Add(@$"{domain}\{user}");
                }
            }

            // Add JA3 fingerprint info for this IP
            var ja3List = Ja3Fingerprints
                .Where(j => j.SourceIp == ipAddress)
                .Select(j => j.Ja3Hash)
                .Distinct()
                .ToList();

            return new NetworkNode()
            {
                IpAddress = ipAddress,
                OpenPorts = this.OpenPorts[ipAddress],
                TcpSessionsCount = tcpSessionsCount,
                UdpStreamsCount = udpSessionsCount,
                DnsMappings = GetNodeDnsMappings(ipAddress),
                SentData = sentData,
                ReceiveData = receivedData,
                Domains = domains,
                DomainUsers = domainUsers
            };
        }

        public string GetNodeDataJson(string ipAddress)
        {
            return JsonConvert.SerializeObject(GetNode(ipAddress));
        }

        private HashSet<string> GetNodeDnsMappings(string ipAddress)
        {
            return this.DnsMappings
                       .Where(d => d.Destination == ipAddress)
                       .Select(d => d.Query)
                       .ToHashSet();
        }

        public List<NetworkNode> GetAllNodes()
        {
            return OpenPorts.Keys.Select(n => GetNode(n)).ToList();
        }

    }

    public static class Extensions
    {
        public static HashSet<T> ToHashSet<T>(
            this IEnumerable<T> source,
            IEqualityComparer<T> comparer = null)
        {
            return new HashSet<T>(source, comparer);
        }
    }

}
