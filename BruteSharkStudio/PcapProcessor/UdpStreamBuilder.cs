using System;
using System.Collections.Generic;
using System.Linq;
using PcapProcessor.Objects;

namespace PcapProcessor.Objects
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Updated UdpStreamBuilder to work with the rewritten time-gap-based UdpRecon.
    // Groups UDP packets into bi-directional sessions using 5-tuple matching.
    class UdpStreamBuilder
    {
        private Dictionary<UdpSession, UdpRecon> _sessions;

        public IEnumerable<UdpSession> Sessions
        {
            get
            {
                return this._sessions.Select(kvp => new UdpSession()
                {
                    SourceIp = kvp.Key.SourceIp,
                    DestinationIp = kvp.Key.DestinationIp,
                    SourcePort = kvp.Key.SourcePort,
                    DestinationPort = kvp.Key.DestinationPort,
                    Data = kvp.Value.Data,
                    Packets = kvp.Value.Packets.Select(p => new PcapProcessor.UdpPacket()
                    {
                        SourceIp = ((PacketDotNet.IPPacket)p.ParentPacket).SourceAddress.ToString(),
                        DestinationIp = ((PacketDotNet.IPPacket)p.ParentPacket).DestinationAddress.ToString(),
                        SourcePort = p.SourcePort,
                        DestinationPort = p.DestinationPort,
                        Data = p.PayloadData
                    }).ToList()
                });
            }
            private set { }
        }

        public UdpStreamBuilder()
        {
            this._sessions = new Dictionary<UdpSession, UdpRecon>();
        }

        public void HandlePacket(PacketDotNet.UdpPacket udpPacket)
        {
            var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;

            var session = new UdpSession()
            {
                SourceIp = ipPacket.SourceAddress.ToString(),
                SourcePort = udpPacket.SourcePort,
                DestinationIp = ipPacket.DestinationAddress.ToString(),
                DestinationPort = udpPacket.DestinationPort
            };

            if (!_sessions.ContainsKey(session))
            {
                var recon = new UdpRecon();
                _sessions.Add(session, recon);
            }

            _sessions[session].AppendPacket(udpPacket);
        }

        public void Clear()
        {
            foreach (var recon in _sessions.Values)
                recon.Dispose();
            this._sessions.Clear();
        }
    }
}
