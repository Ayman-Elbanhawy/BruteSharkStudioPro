using System;
using System.Text;

namespace PcapAnalyzer
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // Ported from PCredz LDAP Simple Bind extraction algorithm by Laurent Gaffie.
    // Parses LDAP v3 Simple Bind requests (RFC 4511) to extract cleartext
    // Distinguished Name (DN) and password on port 389 (or 636 for LDAPS).
    public class LdapSimpleBindParser : IPasswordParser
    {
        // LDAP message envelope: 0x30 = SEQUENCE tag
        // BindRequest: 0x60 = APPLICATION[0] constructed
        // Version: 0x02 = INTEGER
        // Name: 0x04 = OCTET STRING
        // Authentication: 0x80 = context-specific [0] primitive (simple bind password)

        public NetworkLayerObject Parse(UdpPacket udpPacket)
        {
            return ParseLdapBind(udpPacket.Data, udpPacket.SourceIp, udpPacket.DestinationIp, "UDP");
        }

        public NetworkLayerObject Parse(TcpPacket tcpPacket)
        {
            return ParseLdapBind(tcpPacket.Data, tcpPacket.SourceIp, tcpPacket.DestinationIp, "TCP");
        }

        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            // LDAP bind can span multiple TCP packets, try full session data
            if (tcpSession.Data != null && tcpSession.Data.Length > 10)
            {
                // Find each LDAP message in the TCP stream
                int offset = 0;
                while (offset < tcpSession.Data.Length - 10)
                {
                    int msgStart = Utilities.SearchForSubarray(tcpSession.Data, 
                        new byte[] { 0x30 }, offset);
                    if (msgStart < 0) break;

                    // Extract up to 64KB of LDAP payload
                    int extractLen = Math.Min(tcpSession.Data.Length - msgStart, 65535);
                    byte[] ldapMsg = new byte[extractLen];
                    Array.Copy(tcpSession.Data, msgStart, ldapMsg, 0, extractLen);
                    
                    var result = ParseLdapBind(ldapMsg, tcpSession.SourceIp, tcpSession.DestinationIp, "TCP");
                    if (result != null) return result;

                    offset = msgStart + 1;
                }
            }
            return null;
        }

        private NetworkLayerObject ParseLdapBind(byte[] payload, string sourceIp, string destinationIp, string protocol)
        {
            try
            {
                if (payload == null || payload.Length < 10)
                    return null;

                // LDAP packets start with ASN.1 SEQUENCE (0x30)
                if (payload[0] != 0x30)
                    return null;

                int pos = 1;
                int outerLength = ReadAsn1Length(payload, ref pos);
                if (outerLength <= 0 || pos + outerLength > payload.Length)
                    return null;

                int endPos = pos + outerLength;

                // Skip message ID (INTEGER tag 0x02)
                if (pos >= endPos || payload[pos] != 0x02)
                    return null;
                pos++;
                int msgIdLen = ReadAsn1Length(payload, ref pos);
                pos += msgIdLen;

                // Look for BindRequest tag (0x60 = APPLICATION[0] constructed)
                if (pos >= endPos || payload[pos] != 0x60)
                    return null;
                pos++;
                ReadAsn1Length(payload, ref pos); // skip bind request length

                // Skip LDAP version (INTEGER — value should be 3)
                if (pos + 3 > endPos || payload[pos] != 0x02)
                    return null;
                pos++;
                int versionLen = ReadAsn1Length(payload, ref pos);
                pos += versionLen;

                // Read DN (OCTET STRING tag 0x04)
                if (pos + 2 > endPos || payload[pos] != 0x04)
                    return null;
                pos++;
                int dnLen = ReadAsn1Length(payload, ref pos);
                if (pos + dnLen > endPos)
                    return null;

                string dn = Encoding.UTF8.GetString(payload, pos, dnLen);
                pos += dnLen;

                // Read authentication field
                if (pos + 2 > endPos)
                {
                    // Anonymous bind or simple auth with no password
                    return new NetworkPassword()
                    {
                        Protocol = "LDAP Simple Bind",
                        Username = dn,
                        Password = "(anonymous/empty)",
                        Source = sourceIp,
                        Destination = destinationIp
                    };
                }

                // Check for simple auth password: context-specific [0] (0x80)
                if (payload[pos] == 0x80)
                {
                    pos++;
                    int pwdLen = ReadAsn1Length(payload, ref pos);

                    if (pwdLen == 0)
                    {
                        return new NetworkPassword()
                        {
                            Protocol = "LDAP Simple Bind",
                            Username = dn,
                            Password = "(empty)",
                            Source = sourceIp,
                            Destination = destinationIp
                        };
                    }

                    if (pos + pwdLen > endPos)
                        return null;

                    string password = Encoding.UTF8.GetString(payload, pos, pwdLen);

                    return new NetworkPassword()
                    {
                        Protocol = "LDAP Simple Bind",
                        Username = dn,
                        Password = password,
                        Source = sourceIp,
                        Destination = destinationIp
                    };
                }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// Read ASN.1 BER/DER length field. Handles both short form (1 byte)
        /// and long form (1+n bytes). Updates position past the length field.
        /// </summary>
        private static int ReadAsn1Length(byte[] data, ref int pos)
        {
            if (pos >= data.Length)
                return -1;

            int firstByte = data[pos++];

            if ((firstByte & 0x80) == 0)
            {
                // Short form: length in lower 7 bits
                return firstByte;
            }
            else
            {
                // Long form: number of subsequent length bytes in lower 7 bits
                int numBytes = firstByte & 0x7F;
                if (numBytes == 0 || pos + numBytes > data.Length)
                    return -1;

                int length = 0;
                for (int i = 0; i < numBytes; i++)
                {
                    length = (length << 8) | data[pos++];
                }
                return length;
            }
        }
    }
}
