// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// DHCP Snooping Module for BruteShark Studio.
// Detects rogue DHCP servers, DHCP starvation attacks, and extracts
// DHCP lease information (IP assignments, hostnames, vendor info).
//
// DHCP runs on UDP ports 67 (server) and 68 (client).
// Rogue DHCP detection: identifies multiple DHCP OFFER/ACK sources
// on the same subnet, which indicates an unauthorized DHCP server.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PcapAnalyzer
{
    public class DhcpSnoopingModule : IModule
    {
        public string Name => "DHCP Snooping";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // DHCP Message Type option (53)
        private const byte DhcpOptionMessageType = 53;
        private const byte DhcpOptionRequestedIp = 50;
        private const byte DhcpOptionHostName = 12;
        private const byte DhcpOptionVendorClassId = 60;
        private const byte DhcpOptionParameterRequestList = 55;

        // DHCP message types
        private const byte DhcpDiscover = 1;
        private const byte DhcpOffer = 2;
        private const byte DhcpRequest = 3;
        private const byte DhcpDecline = 4;
        private const byte DhcpAck = 5;
        private const byte DhcpNak = 6;
        private const byte DhcpRelease = 7;

        // Track DHCP servers seen on this network
        private readonly ConcurrentDictionary<string, DhcpServerRecord> _dhcpServers;
        // Track DHCP client activity
        private readonly ConcurrentBag<DhcpLease> _leases;
        // Discovery flood tracking
        private readonly ConcurrentDictionary<string, int> _discoverCount;

        public DhcpSnoopingModule()
        {
            _dhcpServers = new ConcurrentDictionary<string, DhcpServerRecord>();
            _leases = new ConcurrentBag<DhcpLease>();
            _discoverCount = new ConcurrentDictionary<string, int>();
        }

        public void Analyze(UdpPacket udpPacket)
        {
            if (udpPacket.DestinationPort != 67 && udpPacket.DestinationPort != 68 &&
                udpPacket.SourcePort != 67 && udpPacket.SourcePort != 68)
                return;

            ProcessDhcpPacket(udpPacket.Data, udpPacket.SourceIp, udpPacket.DestinationIp,
                udpPacket.SourcePort, udpPacket.DestinationPort);
        }

        public void Analyze(TcpPacket tcpPacket) { }
        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        private void ProcessDhcpPacket(byte[] data, string srcIp, string dstIp, int sp, int dp)
        {
            if (data == null || data.Length < 240) return; // DHCP min: 240 bytes

            try
            {
                // Parse DHCP header
                int op = data[0];           // 1=BOOTREQUEST, 2=BOOTREPLY
                // bytes 1-15: htype, hlen, hops, xid, secs, flags
                // bytes 16-19: ciaddr (client IP)
                // bytes 20-23: yiaddr (your IP)
                byte[] yiaddr = { data[20], data[21], data[22], data[23] };
                // bytes 28-43: chaddr (client MAC, 16 bytes)
                string clientMac = string.Join(":", Enumerable.Range(28, 6)
                    .Select(i => data[i].ToString("X2")));

                // Parse DHCP options (starts at byte 240 after BOOTP header)
                var options = ParseDhcpOptions(data, 240);

                // Get message type
                if (!options.ContainsKey(DhcpOptionMessageType)) return;
                byte msgType = (byte)options[DhcpOptionMessageType];

                bool isServerReply = op == 2; // BOOTREPLY from server

                string yiaddrStr = $"{yiaddr[0]}.{yiaddr[1]}.{yiaddr[2]}.{yiaddr[3]}";
                string hostname = options.ContainsKey(DhcpOptionHostName)
                    ? Encoding.ASCII.GetString((byte[])options[DhcpOptionHostName]) : "";
                string vendorClass = options.ContainsKey(DhcpOptionVendorClassId)
                    ? Encoding.ASCII.GetString((byte[])options[DhcpOptionVendorClassId]) : "";

                // Track DHCP servers (for rogue detection)
                if (isServerReply && (msgType == DhcpOffer || msgType == DhcpAck))
                {
                    var record = _dhcpServers.GetOrAdd(srcIp, _ => new DhcpServerRecord
                    {
                        ServerIp = srcIp,
                        FirstSeen = DateTime.UtcNow
                    });

                    lock (record)
                    {
                        record.OfferCount++;
                        record.LastSeen = DateTime.UtcNow;
                        record.LeasedIps.Add(yiaddrStr);
                    }

                    // Check for rogue DHCP
                    if (_dhcpServers.Count >= 2)
                    {
                        var servers = _dhcpServers.Values.ToList();
                        if (servers.Any(s => s.OfferCount >= 3))
                        {
                            EmitAlert("DHCP", "Rogue DHCP Server Detected",
                                $"{_dhcpServers.Count} DHCP servers detected. " +
                                $"Servers: {string.Join(", ", _dhcpServers.Keys)}. " +
                                "Multiple DHCP servers on the same subnet indicate a rogue DHCP attack.",
                                "CRITICAL");
                        }
                    }
                }

                // Track DHCP leases
                if (msgType == DhcpAck && isServerReply)
                {
                    _leases.Add(new DhcpLease
                    {
                        ServerIp = srcIp,
                        ClientMac = clientMac,
                        AssignedIp = yiaddrStr,
                        Hostname = hostname,
                        VendorClass = vendorClass,
                        Timestamp = DateTime.UtcNow
                    });

                    EmitFinding(new DhcpLease
                    {
                        ServerIp = srcIp,
                        ClientMac = clientMac,
                        AssignedIp = yiaddrStr,
                        Hostname = hostname,
                        VendorClass = vendorClass,
                        Timestamp = DateTime.UtcNow
                    });
                }

                // Detect DHCP starvation (flood of DISCOVER from same MAC)
                if (msgType == DhcpDiscover)
                {
                    _discoverCount.AddOrUpdate(clientMac, 1, (_, c) => c + 1);
                    if (_discoverCount.TryGetValue(clientMac, out int count) && count > 20)
                    {
                        EmitAlert("DHCP", "DHCP Starvation Attack",
                            $"Client {clientMac} sent {count} DHCP DISCOVER packets. " +
                            "This may indicate a DHCP starvation attack.",
                            "HIGH");
                    }
                }
            }
            catch { }
        }

        private Dictionary<byte, object> ParseDhcpOptions(byte[] data, int startOffset)
        {
            var options = new Dictionary<byte, object>();
            if (startOffset + 4 > data.Length) return options;

            // First 4 bytes are magic cookie: 99, 130, 83, 99
            if (data[startOffset] != 99 || data[startOffset + 1] != 130 ||
                data[startOffset + 2] != 83 || data[startOffset + 3] != 99)
                return options;

            int pos = startOffset + 4;
            while (pos < data.Length)
            {
                byte optionCode = data[pos];
                if (optionCode == 255) break; // End option
                if (optionCode == 0) { pos++; continue; } // Pad

                pos++;
                if (pos >= data.Length) break;
                byte length = data[pos];
                pos++;

                if (pos + length > data.Length) break;
                byte[] value = new byte[length];
                Array.Copy(data, pos, value, 0, length);
                options[optionCode] = value.Length == 1 && value[0] < 128
                    ? (object)(int)value[0] : value;

                pos += length;
            }

            return options;
        }

        private void EmitAlert(string protocol, string type, string details, string severity)
        {
            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = new PayloadAlert
                {
                    AlertType = type,
                    Severity = severity,
                    Details = details,
                    Protocol = protocol,
                    Timestamp = DateTime.UtcNow
                }
            });
        }

        private void EmitFinding(DhcpLease lease)
        {
            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = lease
            });
        }

        public List<DhcpServerRecord> GetDhcpServers() => _dhcpServers.Values.ToList();
        public List<DhcpLease> GetLeases() => _leases.ToList();
    }

    public class DhcpServerRecord
    {
        public string ServerIp { get; set; }
        public int OfferCount { get; set; }
        public HashSet<string> LeasedIps { get; set; } = new();
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public class DhcpLease : NetworkLayerObject
    {
        public string ServerIp { get; set; }
        public string ClientMac { get; set; }
        public string AssignedIp { get; set; }
        public string Hostname { get; set; }
        public string VendorClass { get; set; }
        public DateTime Timestamp { get; set; }

        public override string ToString()
            => $"DHCP: {ClientMac} → {AssignedIp} [{Hostname}] ({VendorClass}) via {ServerIp}";
    }
}
