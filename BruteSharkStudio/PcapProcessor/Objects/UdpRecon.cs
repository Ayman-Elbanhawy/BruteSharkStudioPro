using System;
using System.Collections.Generic;
using System.Net;

namespace PcapProcessor
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Rewritten UDP stream reconstruction using time-gap heuristics.
    // UDP has no sequence numbers, so we reconstruct "sessions" by grouping
    // packets between the same 5-tuple that arrive within a configurable
    // idle timeout window.

    /// <summary>
    /// Reconstructs a logical UDP "session" from individual UDP packets.
    /// Packets are appended in arrival order. A gap larger than SessionIdleTimeout
    /// is treated as a session boundary.
    /// </summary>
    public class UdpRecon : IDisposable
    {
        // Default: 5 seconds of silence marks end of UDP session
        public static TimeSpan DefaultSessionIdleTimeout = TimeSpan.FromSeconds(5);

        private readonly List<PacketDotNet.UdpPacket> _packets;
        private readonly List<byte> _dataBuffer;
        private DateTime _lastPacketTime;
        private bool _disposed;

        public byte[] Data => _dataBuffer.ToArray();
        public bool EmptyStream => _packets.Count == 0;
        public int PacketCount => _packets.Count;
        public int TotalBytes => _dataBuffer.Count;

        internal IReadOnlyList<PacketDotNet.UdpPacket> Packets => _packets.AsReadOnly();

        public UdpRecon()
        {
            _packets = new List<PacketDotNet.UdpPacket>();
            _dataBuffer = new List<byte>();
            _lastPacketTime = DateTime.MinValue;
            _disposed = false;
        }

        /// <summary>
        /// Appends the UDP packet payload to the reconstructed stream.
        /// </summary>
        public void AppendPacket(PacketDotNet.UdpPacket udpPacket)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(UdpRecon));

            _packets.Add(udpPacket);

            var payload = udpPacket.PayloadData;
            if (payload != null && payload.Length > 0)
            {
                _dataBuffer.AddRange(payload);
            }

            _lastPacketTime = DateTime.UtcNow;
        }

        /// <summary>
        /// Returns true if the given packet would belong to this session
        /// based on the idle timeout.
        /// </summary>
        public bool IsSessionTimedOut(TimeSpan idleTimeout)
        {
            if (_lastPacketTime == DateTime.MinValue)
                return false;

            return (DateTime.UtcNow - _lastPacketTime) > idleTimeout;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _packets.Clear();
                _dataBuffer.Clear();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
