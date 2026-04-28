// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// Interactive Session Data Viewer for BruteShark Studio.
// Provides protocol-aware hex dump formatting with ASCII preview,
// protocol syntax highlighting, search capabilities, and export.
//
// Format: Offset  Hex bytes (16 per row)  ASCII preview
//  00000000  48 54 54 50 2F 31 2E 31  20 32 30 30 20 4F 4B 0D  |HTTP/1.1 200 OK.|

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer
{
    /// <summary>
    /// Generates formatted hex dumps with protocol-aware highlighting hints.
    /// </summary>
    public class SessionViewer
    {
        private readonly byte[] _data;
        private readonly string _protocolHint;

        public int DataLength => _data.Length;
        public string ProtocolHint => _protocolHint;

        public SessionViewer(byte[] data, string protocolHint = null)
        {
            _data = data ?? Array.Empty<byte>();
            _protocolHint = protocolHint;
        }

        /// <summary>
        /// Generate a standard hex dump with ASCII preview.
        /// </summary>
        public string GenerateHexDump(int maxBytes = -1, int startOffset = 0)
        {
            if (_data.Length == 0) return "(empty)";

            int length = maxBytes > 0 ? Math.Min(maxBytes, _data.Length - startOffset) : _data.Length - startOffset;
            if (length <= 0) return "(empty range)";

            var sb = new StringBuilder();
            int rows = (length + 15) / 16;

            for (int row = 0; row < rows; row++)
            {
                int rowOffset = startOffset + row * 16;
                sb.Append($"{rowOffset:X8}  "); // Offset

                // Hex bytes (split into two 8-byte groups)
                for (int col = 0; col < 16; col++)
                {
                    if (col == 8) sb.Append(' '); // Middle gap

                    if (rowOffset + col < _data.Length && rowOffset + col < startOffset + length)
                    {
                        sb.Append($"{_data[rowOffset + col]:X2} ");
                    }
                    else
                    {
                        sb.Append("   "); // Padding
                    }
                }

                sb.Append(" |"); // ASCII start

                for (int col = 0; col < 16; col++)
                {
                    if (rowOffset + col < _data.Length && rowOffset + col < startOffset + length)
                    {
                        byte b = _data[rowOffset + col];
                        sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                    }
                    else
                    {
                        sb.Append(' ');
                    }
                }

                sb.AppendLine("|");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Generate an annotated hex dump with protocol field highlighting marks.
        /// Returns a list of (offset, length, label) annotations.
        /// </summary>
        public List<ProtocolAnnotation> GetProtocolAnnotations()
        {
            var annotations = new List<ProtocolAnnotation>();

            if (_data.Length == 0) return annotations;

            // Auto-detect protocol and annotate known structures
            if (_protocolHint?.Contains("HTTP") == true || LooksLikeHttp())
                AnnotateHttp(annotations);
            else if (_protocolHint?.Contains("TLS") == true || LooksLikeTls())
                AnnotateTls(annotations);
            else if (_protocolHint?.Contains("DNS") == true || LooksLikeDns())
                AnnotateDns(annotations);
            else if (_protocolHint?.Contains("SMB") == true || LooksLikeSmb())
                AnnotateSmb(annotations);

            return annotations;
        }

        /// <summary>
        /// Search for text or hex pattern in the data.
        /// Returns list of matching offsets.
        /// </summary>
        public List<int> Search(string query, bool caseSensitive = false)
        {
            var results = new List<int>();
            if (string.IsNullOrWhiteSpace(query) || _data.Length == 0) return results;

            // Try hex search first (space-separated hex bytes like "48 54 54 50")
            string hexQuery = query.Replace(" ", "").Replace("-", "");
            if (hexQuery.Length >= 2 && hexQuery.Length % 2 == 0 && hexQuery.All(c => Uri.IsHexDigit(c)))
            {
                byte[] pattern = new byte[hexQuery.Length / 2];
                for (int i = 0; i < hexQuery.Length; i += 2)
                    pattern[i / 2] = Convert.ToByte(hexQuery.Substring(i, 2), 16);

                int pos = 0;
                while ((pos = Utilities.SearchForSubarray(_data, pattern, pos)) >= 0)
                {
                    results.Add(pos);
                    pos += pattern.Length;
                }
            }
            else
            {
                // Text search
                StringComparison sc = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
                byte[] queryBytes = Encoding.UTF8.GetBytes(query);
                int pos = 0;
                while ((pos = Utilities.SearchForSubarray(_data, queryBytes, pos)) >= 0)
                {
                    results.Add(pos);
                    pos += queryBytes.Length;
                }

                if (results.Count == 0)
                {
                    // Try ASCII encoding
                    queryBytes = Encoding.ASCII.GetBytes(query);
                    pos = 0;
                    while ((pos = Utilities.SearchForSubarray(_data, queryBytes, pos)) >= 0)
                    {
                        results.Add(pos);
                        pos += queryBytes.Length;
                    }
                }
            }

            return results;
        }

        /// <summary>
        /// Export section of data as raw bytes to a file.
        /// </summary>
        public byte[] ExtractRange(int offset, int length)
        {
            if (offset < 0 || offset >= _data.Length) return Array.Empty<byte>();
            length = Math.Min(length, _data.Length - offset);
            byte[] result = new byte[length];
            Array.Copy(_data, offset, result, 0, length);
            return result;
        }

        // --- Protocol auto-detection helpers ---
        private bool LooksLikeHttp()
        {
            if (_data.Length < 8) return false;
            string start = Encoding.ASCII.GetString(_data, 0, Math.Min(8, _data.Length));
            return start.StartsWith("GET ") || start.StartsWith("POST") || start.StartsWith("HTTP") ||
                   start.StartsWith("PUT ") || start.StartsWith("HEAD") || start.StartsWith("DELE");
        }

        private bool LooksLikeTls()
        {
            if (_data.Length < 3) return false;
            // TLS record: ContentType (0x14-0x17), Version (0x03xx)
            return (_data[0] >= 0x14 && _data[0] <= 0x17) && _data[1] == 0x03;
        }

        private bool LooksLikeDns()
        {
            if (_data.Length < 12) return false;
            // DNS: Transaction ID (2 bytes) + Flags (2 bytes) + counts (8 bytes)
            return _data[2] < 0x80 && (_data[3] & 0x80) == 0;
        }

        private bool LooksLikeSmb()
        {
            if (_data.Length < 4) return false;
            return (_data[0] == 0xFF && _data[1] == 0x53 && _data[2] == 0x4D && _data[3] == 0x42) ||
                   (_data[0] == 0xFE && _data[1] == 0x53 && _data[2] == 0x4D && _data[3] == 0x42);
        }

        // --- Protocol annotation generators ---
        private void AnnotateHttp(List<ProtocolAnnotation> annotations)
        {
            string text = Encoding.ASCII.GetString(_data, 0, Math.Min(_data.Length, 2048));
            int bodyStart = text.IndexOf("\r\n\r\n");
            if (bodyStart > 0)
            {
                annotations.Add(new ProtocolAnnotation(0, bodyStart, "HTTP Headers", "header"));
                annotations.Add(new ProtocolAnnotation(bodyStart + 4, _data.Length - bodyStart - 4, "HTTP Body", "body"));
            }
        }

        private void AnnotateTls(List<ProtocolAnnotation> annotations)
        {
            annotations.Add(new ProtocolAnnotation(0, 1, "Content Type", "field"));
            annotations.Add(new ProtocolAnnotation(1, 2, "TLS Version", "field"));
            annotations.Add(new ProtocolAnnotation(3, 2, "Record Length", "field"));
            if (_data.Length > 5 && _data[5] == 0x01)
                annotations.Add(new ProtocolAnnotation(5, _data.Length - 5, "TLS Handshake", "struct"));
        }

        private void AnnotateDns(List<ProtocolAnnotation> annotations)
        {
            annotations.Add(new ProtocolAnnotation(0, 2, "Transaction ID", "field"));
            annotations.Add(new ProtocolAnnotation(2, 2, "Flags", "field"));
            annotations.Add(new ProtocolAnnotation(4, 2, "Questions", "field"));
            annotations.Add(new ProtocolAnnotation(6, 2, "Answer RRs", "field"));
            annotations.Add(new ProtocolAnnotation(8, 2, "Authority RRs", "field"));
            annotations.Add(new ProtocolAnnotation(10, 2, "Additional RRs", "field"));
            annotations.Add(new ProtocolAnnotation(12, _data.Length - 12, "DNS Data", "struct"));
        }

        private void AnnotateSmb(List<ProtocolAnnotation> annotations)
        {
            annotations.Add(new ProtocolAnnotation(0, 4, "SMB Magic", "field"));
            if (_data.Length > 4)
                annotations.Add(new ProtocolAnnotation(4, _data.Length - 4, "SMB Payload", "struct"));
        }
    }

    /// <summary>
    /// Marks a byte range in the session data with a protocol field label.
    /// </summary>
    public class ProtocolAnnotation
    {
        public int Offset { get; }
        public int Length { get; }
        public string Label { get; }
        public string Category { get; } // "header", "body", "field", "struct"

        public ProtocolAnnotation(int offset, int length, string label, string category)
        {
            Offset = offset;
            Length = length;
            Label = label;
            Category = category;
        }
    }
}
