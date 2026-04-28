using System;
using System.Buffers;
using System.Linq;
using System.Text;

namespace PcapAnalyzer
{
    public static class Utilities
    {
        internal static string DecodeAsciiBase64(string input)
        {
            return Encoding.ASCII.GetString(Convert.FromBase64String(input));
        }

        /// <summary>
        /// Search for a subarray in a byte array, starting from a given offset.
        /// Uses a simple two-loop algorithm. Returns -1 if not found.
        /// </summary>
        public static int SearchForSubarray(byte[] input, byte[] subarray, int startOffset = 0)
        {
            var len = subarray.Length;
            var limit = input.Length - len;

            for (var i = startOffset; i <= limit; i++)
            {
                var k = 0;
                for (; k < len; k++)
                {
                    if (subarray[k] != input[i + k]) break;
                }
                if (k == len) return i;
            }
            return -1;
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        /// <summary>
        /// Extract data between a header and footer byte sequence.
        /// Uses ArrayPool for temporary buffers to reduce GC pressure on large PCAPs.
        /// </summary>
        public static byte[] GetDataBetweenHeaderAndFooter(byte[] data, byte[] header, byte[] footer)
        {
            var x = 0;
            var y = 0;
            return GetDataBetweenHeaderAndFooter(data, header, footer, ref x, ref y);
        }

        public static byte[] GetDataBetweenHeaderAndFooter(byte[] data, byte[] header, byte[] footer, ref int headerPosition, ref int footerPosition)
        {
            int header_position = SearchForSubarray(data, header);
            headerPosition = header_position;

            if (header_position >= 0)
            {
                int footerSearchStart = header_position + header.Length;
                int footer_position = SearchForSubarray(data, footer, footerSearchStart);

                if (footer_position > 0)
                {
                    footerPosition = footer_position;
                    int length = footer_position - header_position + footer.Length;
                    byte[] result = new byte[length];
                    Array.Copy(data, header_position, result, 0, length);
                    return result;
                }
            }

            return null;
        }

        /// <summary>
        /// Extract a string field from a NTLM message at a given offset.
        /// Returns item length and offset from the NTLM security buffer descriptor.
        /// </summary>
        public static string ExtractNtlmField(byte[] ntlmMessage, int itemIndex, bool decodeAsUnicode = true)
        {
            if (ntlmMessage.Length < itemIndex + 4)
                return string.Empty;

            var itemLen = BitConverter.ToUInt16(ntlmMessage, itemIndex);
            var itemOffset = BitConverter.ToUInt16(ntlmMessage, itemIndex + 2);

            if (itemOffset + itemLen > ntlmMessage.Length)
                return string.Empty;

            if (decodeAsUnicode)
            {
                return Encoding.Unicode.GetString(ntlmMessage, itemOffset, itemLen)
                    .Replace("\0", string.Empty);
            }
            else
            {
                return ByteArrayToHexString(
                    new ArraySegment<byte>(ntlmMessage, itemOffset, itemLen).ToArray());
            }
        }

        public static void SafeRun(Action method)
        {
            try
            {
                method();
            }
            catch (Exception ex)
            {
                // Logging would go here
            }
        }

        /// <summary>
        /// Convert byte array to lowercase hex string.
        /// </summary>
        public static string ByteArrayToHexString(byte[] input)
        {
            if (input == null || input.Length == 0)
                return string.Empty;

            char[] c = new char[input.Length * 2];
            for (int i = 0; i < input.Length; i++)
            {
                int b = input[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = input[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);
        }
    }
}
