// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// File hashing utilities and export helpers for BruteShark Studio.
// Computes SHA-256, MD5, and SHA-1 hashes for extracted network files.
// Used for IOC generation, VirusTotal lookups, and evidence chain-of-custody.

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PcapAnalyzer
{
    /// <summary>
    /// Cryptographic hash results for a single file.
    /// </summary>
    public class FileHashResult
    {
        public string Sha256 { get; set; }
        public string Md5 { get; set; }
        public string Sha1 { get; set; }
        public long FileSize { get; set; }

        public override string ToString()
            => $"SHA256: {Sha256} MD5: {Md5} Size: {FileSize} bytes";
    }

    /// <summary>
    /// File hashing and export utilities.
    /// </summary>
    public static class FileHasher
    {
        /// <summary>
        /// Compute all hash types for a byte array and return the result.
        /// Uses a single pass to avoid re-reading.
        /// </summary>
        public static FileHashResult ComputeHashes(byte[] data)
        {
            if (data == null || data.Length == 0)
                return null;

            using var sha256 = SHA256.Create();
            using var md5 = MD5.Create();
            using var sha1 = SHA1.Create();

            return new FileHashResult
            {
                Sha256 = BytesToHex(sha256.ComputeHash(data)),
                Md5 = BytesToHex(md5.ComputeHash(data)),
                Sha1 = BytesToHex(sha1.ComputeHash(data)),
                FileSize = data.Length
            };
        }

        /// <summary>
        /// Compute SHA-256 for a byte array.
        /// </summary>
        public static string ComputeSha256(byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            using var sha256 = SHA256.Create();
            return BytesToHex(sha256.ComputeHash(data));
        }

        /// <summary>
        /// Compute MD5 for a byte array.
        /// </summary>
        public static string ComputeMd5(byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            using var md5 = MD5.Create();
            return BytesToHex(md5.ComputeHash(data));
        }

        /// <summary>
        /// Compute SHA-256 for a file on disk.
        /// </summary>
        public static string ComputeFileSha256(string filePath)
        {
            if (!File.Exists(filePath)) return null;
            using var stream = File.OpenRead(filePath);
            using var sha256 = SHA256.Create();
            return BytesToHex(sha256.ComputeHash(stream));
        }

        private static string BytesToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }
    }

    /// <summary>
    /// Extends NetworkFile with hash computation for evidence chain-of-custody.
    /// </summary>
    public static class NetworkFileExtensions
    {
        public static FileHashResult ComputeHashes(this NetworkFile file)
        {
            if (file.FileData == null || file.FileData.Length == 0)
                return null;
            return FileHasher.ComputeHashes(file.FileData);
        }

        public static string GetChainOfCustodyLabel(this NetworkFile file)
        {
            var hash = file.ComputeHashes();
            if (hash == null) return file.ToString();

            return $"File: {file.Source}->{file.Destination}.{file.Extention} " +
                   $"[Size: {hash.FileSize} bytes, SHA256: {hash.Sha256.Substring(0, 16)}...]";
        }
    }
}
