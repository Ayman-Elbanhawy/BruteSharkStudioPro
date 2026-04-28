using System;
using System.Text;

namespace PcapAnalyzer
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Extracts SNMP v1/v2c community strings from SNMP GET/SET requests.
    // SNMP v1/v2c sends the community string in cleartext as an ASN.1 OCTET STRING.
    // Community strings are often "public" (read) or "private" (write).
    // Ported from PCredz and NetworkMiner reference implementations.
    public class SnmpCommunityParser : IPasswordParser
    {
        // SNMP runs on ports 161 (agent) and 162 (trap)
        private static bool IsSnmpPort(int port)
        {
            return port == 161 || port == 162;
        }

        public NetworkLayerObject Parse(UdpPacket udpPacket)
        {
            return ExtractSnmpCommunity(udpPacket.Data, udpPacket.SourceIp, udpPacket.DestinationIp);
        }

        public NetworkLayerObject Parse(TcpPacket tcpPacket)
        {
            return ExtractSnmpCommunity(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp);
        }

        public NetworkLayerObject Parse(TcpSession tcpSession) => null;

        private NetworkLayerObject ExtractSnmpCommunity(byte[] payload, string sourceIp, string destinationIp)
        {
            try
            {
                if (payload == null || payload.Length < 4)
                    return null;

                // SNMP messages start with ASN.1 SEQUENCE (0x30)
                if (payload[0] != 0x30)
                    return null;

                int pos = 1;
                int outerLength = ReadAsn1Length(payload, ref pos);
                if (outerLength <= 0 || pos + outerLength > payload.Length)
                    return null;

                // SNMP version: INTEGER (0x02)
                if (pos >= payload.Length || payload[pos] != 0x02)
                    return null;
                pos++;
                int versionLen = ReadAsn1Length(payload, ref pos);

                // Check version: 0 = SNMPv1, 1 = SNMPv2c
                if (versionLen < 1 || pos >= payload.Length)
                    return null;
                int version = payload[pos];
                pos += versionLen;

                if (version > 1) // SNMPv3 is encrypted, can't extract
                    return null;

                // Community string: OCTET STRING (0x04)
                if (pos >= payload.Length || payload[pos] != 0x04)
                    return null;
                pos++;
                int communityLen = ReadAsn1Length(payload, ref pos);
                if (communityLen <= 0 || pos + communityLen > payload.Length)
                    return null;

                string community = Encoding.ASCII.GetString(payload, pos, communityLen);

                // Skip known defaults with a note
                string protocol = version == 0 ? "SNMPv1" : "SNMPv2c";
                string note = community switch
                {
                    "public" => " (default read-only community)",
                    "private" => " (default read-write community)",
                    _ => ""
                };

                // Determine if this is a GET/SET/TRAP based on PDU type
                int pduPos = pos + communityLen;
                string operation = "Unknown";
                if (pduPos < payload.Length)
                {
                    operation = payload[pduPos] switch
                    {
                        0xA0 => "GET",
                        0xA1 => "GETNEXT",
                        0xA2 => "RESPONSE",
                        0xA3 => "SET",
                        0xA4 => "TRAPv1",
                        0xA5 => "GETBULK",
                        0xA6 => "INFORM",
                        0xA7 => "TRAPv2",
                        _ => "Unknown"
                    };
                }

                return new NetworkPassword()
                {
                    Protocol = $"{protocol} Community String",
                    Username = operation,
                    Password = community + note,
                    Source = sourceIp,
                    Destination = destinationIp
                };
            }
            catch { }

            return null;
        }

        private static int ReadAsn1Length(byte[] data, ref int pos)
        {
            if (pos >= data.Length) return -1;
            int firstByte = data[pos++];
            if ((firstByte & 0x80) == 0)
                return firstByte;

            int numBytes = firstByte & 0x7F;
            if (numBytes == 0 || pos + numBytes > data.Length) return -1;

            int length = 0;
            for (int i = 0; i < numBytes; i++)
                length = (length << 8) | data[pos++];
            return length;
        }
    }
}
