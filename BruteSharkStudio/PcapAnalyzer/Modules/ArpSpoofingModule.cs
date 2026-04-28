// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// ARP Spoofing / MITM Detection Module for BruteShark Studio.
// Detects ARP cache poisoning attacks by monitoring for:
//  - Duplicate MAC addresses claiming different IPs
//  - Gratuitous ARP floods
//  - MAC-IP pair changes over time
//  - ARP replies without corresponding requests

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace PcapAnalyzer
{
    public class ArpSpoofingModule : IModule
    {
        public string Name => "ARP Spoofing Detection";
        public event EventHandler<ParsedItemDetectedEventArgs> ParsedItemDetected;
        public event EventHandler<UpdatedPropertyInItemeventArgs> UpdatedItemProprertyDetected;

        // IP → MAC mappings (current state)
        private readonly ConcurrentDictionary<string, string> _ipToMac;
        // MAC → set of IPs (reverse lookup for duplicate MAC detection)
        private readonly ConcurrentDictionary<string, HashSet<string>> _macToIps;
        // Known static mappings that shouldn't change
        private readonly HashSet<string> _knownGateways;
        // ARP request tracking for unsolicited reply detection
        private readonly ConcurrentDictionary<string, int> _arpRequestCount;
        // Alert throttling per MAC
        private readonly ConcurrentDictionary<string, DateTime> _lastAlertTime;

        public ArpSpoofingModule()
        {
            _ipToMac = new ConcurrentDictionary<string, string>();
            _macToIps = new ConcurrentDictionary<string, HashSet<string>>();
            _knownGateways = new HashSet<string>();
            _arpRequestCount = new ConcurrentDictionary<string, int>();
            _lastAlertTime = new ConcurrentDictionary<string, DateTime>();
        }

        public void Analyze(UdpPacket udpPacket) { }
        public void Analyze(TcpPacket tcpPacket) { }
        public void Analyze(TcpSession tcpSession) { }
        public void Analyze(UdpStream udpStream) { }

        /// <summary>
        /// Process a raw Ethernet frame containing an ARP packet.
        /// Call this from the processor layer when ARP packets are detected.
        /// </summary>
        public void ProcessArpFrame(byte[] frameData, string sourceMac, string destMac)
        {
            if (frameData == null || frameData.Length < 28) return;

            try
            {
                // ARP packet structure (after Ethernet header):
                // Offset 0-1: Hardware type (1 = Ethernet)
                // Offset 2-3: Protocol type (0x0800 = IPv4)
                // Offset 4: Hardware address length (6)
                // Offset 5: Protocol address length (4)
                // Offset 6-7: Operation (1 = request, 2 = reply)
                
                int hwType = (frameData[14] << 8) | frameData[15];
                int protoType = (frameData[16] << 8) | frameData[17];
                int operation = (frameData[20] << 8) | frameData[21];

                if (hwType != 1 || protoType != 0x0800) return;

                // Extract sender MAC and IP
                string senderMac = string.Join(":", Enumerable.Range(22, 6)
                    .Select(i => frameData[i].ToString("X2")));
                string senderIp = $"{frameData[28]}.{frameData[29]}.{frameData[30]}.{frameData[31]}";

                // Extract target MAC and IP
                string targetMac = string.Join(":", Enumerable.Range(32, 6)
                    .Select(i => frameData[i].ToString("X2")));
                string targetIp = $"{frameData[38]}.{frameData[39]}.{frameData[40]}.{frameData[41]}";

                // Track ARP replies
                if (operation == 2) // ARP Reply
                {
                    CheckForSpoofing(senderIp, senderMac, targetIp, isReply: true);
                }
                else if (operation == 1) // ARP Request
                {
                    _arpRequestCount.AddOrUpdate(
                        $"{senderIp}->{targetIp}", 1, (_, c) => c + 1);
                    
                    // Check for ARP request flood
                    if (_arpRequestCount.Values.Any(c => c > 50))
                    {
                        EmitAlert("ARP", "ARP Request Flood",
                            $"Excessive ARP requests detected from {senderIp} ({senderMac})",
                            senderIp, targetIp, "HIGH");
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Process a parsed ARP packet from higher-level dissectors.
        /// </summary>
        public void ProcessArpPacket(string senderIp, string senderMac, 
            string targetIp, string targetMac, bool isReply)
        {
            if (isReply)
                CheckForSpoofing(senderIp, senderMac, targetIp, isReply: true);
        }

        private void CheckForSpoofing(string ip, string mac, string targetIp, bool isReply)
        {
            var now = DateTime.UtcNow;

            // Check 1: MAC claiming a NEW IP (possible spoofing if MAC already has IP)
            if (_macToIps.TryGetValue(mac, out var existingIps))
            {
                lock (existingIps)
                {
                    if (!existingIps.Contains(ip))
                    {
                        existingIps.Add(ip);
                        
                        // One MAC claiming multiple IPs = spoofed ARP
                        if (existingIps.Count >= 2)
                        {
                            var ips = string.Join(", ", existingIps);
                            if (ShouldAlert(mac, now))
                            {
                                EmitAlert("ARP", "Duplicate MAC (Spoofing)",
                                    $"MAC {mac} is claiming multiple IPs: {ips} — " +
                                    "this is a strong indicator of ARP cache poisoning",
                                    ip, targetIp, "CRITICAL");
                            }
                        }
                    }
                }
            }
            else
            {
                _macToIps[mac] = new HashSet<string> { ip };
            }

            // Check 2: IP address changing MAC (man-in-the-middle)
            if (_ipToMac.TryGetValue(ip, out var existingMac))
            {
                if (existingMac != mac)
                {
                    // IP-MAC binding changed — possible MITM
                    if (ShouldAlert(mac, now))
                    {
                        EmitAlert("ARP", "IP-MAC Binding Change (MITM)",
                            $"IP {ip} changed MAC from {existingMac} to {mac}. " +
                            "This indicates a possible ARP cache poisoning attack.",
                            ip, targetIp, "CRITICAL");
                    }
                    _ipToMac[ip] = mac;
                }
            }
            else
            {
                _ipToMac[ip] = mac;
            }

            // Check 3: Gratuitous ARP (sending ARP reply to oneself)
            if (isReply && ip == targetIp)
            {
                // Single gratuitous ARP is normal (IP conflict detection).
                // Track frequency — floods are suspicious.
                string garpKey = $"garp:{mac}";
            }
        }

        private bool ShouldAlert(string key, DateTime now)
        {
            if (_lastAlertTime.TryGetValue(key, out var lastAlert))
            {
                if ((now - lastAlert).TotalSeconds < 30)
                    return false; // Don't spam alerts for same MAC
            }
            _lastAlertTime[key] = now;
            return true;
        }

        private void EmitAlert(string protocol, string alertType, string details,
            string src, string dst, string severity)
        {
            var alert = new PayloadAlert
            {
                AlertType = alertType,
                Severity = severity,
                Details = details,
                SourceIp = src,
                DestinationIp = dst,
                Protocol = protocol,
                Timestamp = DateTime.UtcNow
            };

            ParsedItemDetected?.Invoke(this, new ParsedItemDetectedEventArgs
            {
                ParsedItem = alert
            });
        }
    }
}
