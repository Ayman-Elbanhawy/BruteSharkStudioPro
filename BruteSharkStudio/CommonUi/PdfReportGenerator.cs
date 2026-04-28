// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// PDF Report Generator for BruteShark Studio.
// Generates professional PDF forensic reports using a minimal embedded
// PDF writer (no external dependencies). Supports:
//  - Executive summary with statistics
//  - Critical findings table
//  - C2 beacon detection results
//  - JA3 fingerprint analysis
//  - Credential extraction summary
//  - Network connection summary
//
// PDF format: https://www.adobe.com/devnet/pdf/pdf_reference.html

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using PcapAnalyzer;

namespace CommonUi
{
    public static class PdfReportGenerator
    {
        // PDF objects counter
        private static int _objectId;

        public static string GeneratePdfReport(NetworkContext context, string caseName = "BruteShark Forensic Report")
        {
            _objectId = 1;
            var pdf = new StringBuilder();
            var pageContent = new StringBuilder();
            var fontId = _objectId++;

            // Start with page content
            pageContent.AppendLine("BT");
            pageContent.AppendLine($"/F{fontId} 12 Tf");
            pageContent.AppendLine("50 750 Td");
            pageContent.AppendLine($"{EscapePdfString(caseName)} Tj");
            pageContent.AppendLine("0 -20 Td");
            pageContent.AppendLine($"/F{fontId} 8 Tf");
            pageContent.AppendLine($"{EscapePdfString($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC | BruteShark Studio v2.0")} Tj");
            pageContent.AppendLine("ET");

            // Summary statistics
            pageContent.AppendLine("BT");
            pageContent.AppendLine("/F1 10 Tf");
            pageContent.AppendLine("50 680 Td");
            pageContent.AppendLine($"{EscapePdfString("=== EXECUTIVE SUMMARY ===")} Tj");
            pageContent.AppendLine("0 -18 Td");
            pageContent.AppendLine($"/F1 9 Tf");
            pageContent.AppendLine($"{EscapePdfString($"Connections: {context.Connections.Count}  |  Hashes: {context.Hashes.Count}  |  DNS: {context.DnsMappings.Count}")} Tj");
            pageContent.AppendLine("0 -14 Td");
            pageContent.AppendLine($"{EscapePdfString($"JA3 Fingerprints: {context.Ja3Count}  |  C2 Beacons: {context.BeaconCount}  |  Detection Matches: {context.DetectionMatches.Count}")} Tj");
            pageContent.AppendLine("ET");

            // Critical findings
            var criticalMatches = context.DetectionMatches
                .Where(m => m.Severity == "Critical" || m.Severity == "High").ToList();
            
            int yPos = 630;
            if (criticalMatches.Any())
            {
                pageContent.AppendLine("BT");
                pageContent.AppendLine($"/F1 10 Tf");
                pageContent.AppendLine($"50 {yPos} Td");
                pageContent.AppendLine($"{EscapePdfString("=== CRITICAL & HIGH SEVERITY FINDINGS ===")} Tj");
                pageContent.AppendLine("0 -16 Td");
                pageContent.AppendLine($"/F1 8 Tf");
                yPos -= 40;

                foreach (var m in criticalMatches.Take(10))
                {
                    if (yPos < 80) { pageContent.AppendLine("ET"); break; }
                    string line = $"[{m.Severity}] {m.RuleName}: {Truncate(m.MatchDetails, 100)}";
                    pageContent.AppendLine($"{EscapePdfString(line)} Tj");
                    pageContent.AppendLine("0 -12 Td");
                    yPos -= 12;
                }
                pageContent.AppendLine("ET");
            }

            // Beacon detections
            if (context.BeaconResults.Any())
            {
                pageContent.AppendLine("BT");
                pageContent.AppendLine($"/F1 10 Tf");
                pageContent.AppendLine($"50 {yPos - 10} Td");
                pageContent.AppendLine($"{EscapePdfString("=== C2 BEACON DETECTIONS ===")} Tj");
                pageContent.AppendLine("0 -16 Td");
                pageContent.AppendLine($"/F1 8 Tf");
                yPos -= 30;

                foreach (var b in context.BeaconResults.Take(10).OrderByDescending(b => b.BeaconScore))
                {
                    if (yPos < 80) break;
                    string line = $"Score:{b.BeaconScore:F0}% {b.PairKey} -> {b.ProbableC2Server} (Int:{b.MeanIntervalSeconds:F1}s,Jitter:{b.JitterRatio:P1})";
                    pageContent.AppendLine($"{EscapePdfString(line)} Tj");
                    pageContent.AppendLine("0 -12 Td");
                    yPos -= 12;
                }
                pageContent.AppendLine("ET");
            }

            // Hashes
            if (context.Hashes.Any())
            {
                pageContent.AppendLine("BT");
                pageContent.AppendLine($"/F1 10 Tf");
                pageContent.AppendLine($"50 {yPos - 10} Td");
                pageContent.AppendLine($"{EscapePdfString($"=== EXTRACTED HASHES ({context.Hashes.Count}) ===")} Tj");
                pageContent.AppendLine("0 -16 Td");
                pageContent.AppendLine($"/F1 7 Tf");
                yPos -= 30;

                foreach (var h in context.Hashes.Take(15))
                {
                    if (yPos < 80) break;
                    string user = h is IDomainCredential dc ? dc.GetUsername() : "";
                    string hashTrunc = h.Hash?.Length > 24 ? h.Hash.Substring(0, 24) + "..." : h.Hash ?? "";
                    string line = $"[{h.HashType}] {user}: {hashTrunc} ({h.Source}->{h.Destination})";
                    pageContent.AppendLine($"{EscapePdfString(line)} Tj");
                    pageContent.AppendLine("0 -11 Td");
                    yPos -= 11;
                }
                pageContent.AppendLine("ET");
            }

            // Build the PDF
            int catalogId = _objectId++;
            int pagesId = _objectId++;
            int pageId = _objectId++;
            int contentId = _objectId++;
            int fontObjId = _objectId++; // Courier font

            var objects = new StringBuilder();

            // Catalog
            objects.AppendLine($"{catalogId} 0 obj << /Type /Catalog /Pages {pagesId} 0 R >> endobj");

            // Pages
            objects.AppendLine($"{pagesId} 0 obj << /Type /Pages /Kids [{pageId} 0 R] /Count 1 >> endobj");

            // Page
            objects.AppendLine($"{pageId} 0 obj << /Type /Page /Parent {pagesId} 0 R /MediaBox [0 0 612 792] /Contents {contentId} 0 R /Resources << /Font << /F1 {fontObjId} 0 R >> >> >> endobj");

            // Content stream
            byte[] compressed = CompressDeflate(Encoding.ASCII.GetBytes(pageContent.ToString()));
            string hexContent = string.Join("", compressed.Select(b => b.ToString("X2")));
            objects.AppendLine($"{contentId} 0 obj << /Length {compressed.Length} /Filter /FlateDecode >> stream\n{hexContent}\nendstream endobj");

            // Font
            objects.AppendLine($"{fontObjId} 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj");

            // File header
            int xrefOffset = 0;
            var fileBytes = new List<byte>();
            string header = "%PDF-1.4\n% BruteShark Studio PDF Report\n";
            fileBytes.AddRange(Encoding.ASCII.GetBytes(header));
            xrefOffset = fileBytes.Count;

            // Build xref table
            var objPositions = new Dictionary<int, int>();
            foreach (var line in objects.ToString().Split('\n'))
            {
                if (line.EndsWith(" endobj"))
                {
                    var parts = line.Split(' ');
                    if (parts.Length >= 2 && int.TryParse(parts[0], out int id))
                    {
                        objPositions[id] = fileBytes.Count;
                    }
                }
                fileBytes.AddRange(Encoding.ASCII.GetBytes(line + "\n"));
            }

            // Write xref
            fileBytes.AddRange(Encoding.ASCII.GetBytes("xref\n"));
            fileBytes.AddRange(Encoding.ASCII.GetBytes($"0 {_objectId}\n"));
            fileBytes.AddRange(Encoding.ASCII.GetBytes($"0000000000 65535 f \n"));
            
            foreach (var kvp in objPositions.OrderBy(k => k.Key))
            {
                fileBytes.AddRange(Encoding.ASCII.GetBytes($"{kvp.Value:D10} 00000 n \n"));
            }

            // Trailer
            fileBytes.AddRange(Encoding.ASCII.GetBytes($"trailer\n<< /Size {_objectId} /Root {catalogId} 0 R >>\n"));
            fileBytes.AddRange(Encoding.ASCII.GetBytes("startxref\n"));
            fileBytes.AddRange(Encoding.ASCII.GetBytes($"{xrefOffset}\n"));
            fileBytes.AddRange(Encoding.ASCII.GetBytes("%%EOF\n"));

            using var ms = new MemoryStream(fileBytes.ToArray());
            using var reader = new StreamReader(ms);
            return reader.ReadToEnd();
        }

        public static string ExportPdfReport(string directory, NetworkContext context, string caseName = null)
        {
            caseName ??= $"BruteShark_Forensic_Report_{DateTime.Now:yyyyMMdd}";
            var pdf = GeneratePdfReport(context, caseName);
            var filePath = Exporting.GetUniqueFilePath(Path.Combine(directory, $"{caseName.Replace(' ', '_')}.pdf"));
            File.WriteAllText(filePath, pdf, Encoding.ASCII);
            return filePath;
        }

        private static string EscapePdfString(string text)
        {
            if (string.IsNullOrEmpty(text)) return "()";
            text = text.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");
            return $"({text})";
        }

        private static string Truncate(string text, int maxLen)
        {
            if (string.IsNullOrEmpty(text)) return "";
            return text.Length <= maxLen ? text : text.Substring(0, maxLen - 3) + "...";
        }

        // Minimal Deflate implementation using System.IO.Compression
        private static byte[] CompressDeflate(byte[] data)
        {
            using var output = new MemoryStream();
            using (var deflate = new System.IO.Compression.DeflateStream(output, System.IO.Compression.CompressionMode.Compress))
            {
                deflate.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }
    }
}
