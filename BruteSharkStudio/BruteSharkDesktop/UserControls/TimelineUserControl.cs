using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    /// <summary>
    /// Chronological timeline of all detected network events — color-coded by type.
    /// </summary>
    public class TimelineUserControl : UserControl
    {
        private DataGridView _timelineGrid;
        private Button _exportButton;

        // Internal list so we can export programmatically
        private readonly List<TimelineEntry> _entries = new List<TimelineEntry>();

        private struct TimelineEntry
        {
            public DateTime Time;
            public string Type;
            public string Source;
            public string Destination;
            public string Summary;
        }

        public TimelineUserControl()
        {
            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.Dock = DockStyle.Fill;

            // ── Top panel with title and export button ──
            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 40,
                BackColor = Color.FromArgb(0x25, 0x25, 0x40)
            };

            var titleLabel = new Label
            {
                Text = "Network Event Timeline — color-coded by type, sorted newest first",
                Location = new Point(10, 10),
                AutoSize = true,
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x25, 0x25, 0x40),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };

            _exportButton = new Button
            {
                Text = "Export Timeline CSV",
                Location = new Point(450, 6),
                Size = new Size(150, 28),
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(0x45, 0x47, 0x5A),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _exportButton.FlatAppearance.BorderColor = Color.FromArgb(0x89, 0xB4, 0xFA);
            _exportButton.Click += ExportCsv;

            topPanel.Controls.Add(titleLabel);
            topPanel.Controls.Add(_exportButton);

            // ── DataGridView ──
            _timelineGrid = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                GridColor = Color.FromArgb(0x45, 0x47, 0x5A),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                Font = new Font("Consolas", 9f)
            };
            _timelineGrid.CellFormatting += TimelineGrid_CellFormatting;

            _timelineGrid.Columns.Add("Time", "Time");
            _timelineGrid.Columns.Add("Type", "Type");
            _timelineGrid.Columns.Add("Source", "Source");
            _timelineGrid.Columns.Add("Destination", "Destination");
            _timelineGrid.Columns.Add("Summary", "Summary");

            StyleGrid(_timelineGrid);

            this.Controls.Add(_timelineGrid);
            this.Controls.Add(topPanel);
        }

        /// <summary>
        /// Add a single event to the timeline.
        /// </summary>
        public void AddEvent(DateTime time, string type, string source, string dest, string summary)
        {
            _entries.Add(new TimelineEntry
            {
                Time = time,
                Type = type,
                Source = source ?? "",
                Destination = dest ?? "",
                Summary = summary ?? ""
            });

            // Rebuild grid sorted descending by time
            RefreshGrid();
        }

        /// <summary>
        /// Auto-populate the timeline from every data source in the network context.
        /// </summary>
        public void LoadFromContext(CommonUi.NetworkContext ctx)
        {
            _entries.Clear();

            if (ctx == null) return;

            // ── Passwords ──
            foreach (var p in ctx.Passwords)
                _entries.Add(MakeEntry(DateTime.Now, "Password", p.Source, p.Destination,
                    $"User: {p.Username} / Pass: {p.Password} [{p.Protocol}]"));

            // ── Hashes ──
            foreach (var h in ctx.Hashes)
                _entries.Add(MakeEntry(DateTime.Now, "Hash", h.Source, h.Destination,
                    $"{h.HashType}: {h.Hash?.Substring(0, Math.Min(h.Hash?.Length ?? 0, 40))}"));

            // ── Connections ──
            foreach (var c in ctx.Connections)
                _entries.Add(MakeEntry(DateTime.Now, "Connection", c.Source, c.Destination,
                    $"{c.Protocol} {c.SrcPort}→{c.DestPort}"));

            // ── Files ──
            foreach (var f in ctx.NetworkFiles)
                _entries.Add(MakeEntry(DateTime.Now, "File", f.Source, f.Destination,
                    $".{f.Extention} ({f.FileSize}B via {f.Algorithm})"));

            // ── DNS Mappings ──
            foreach (var d in ctx.DnsMappings)
                _entries.Add(MakeEntry(DateTime.Now, "DNS", "", d.Destination,
                    $"{d.Query} → {d.Destination}"));

            // ── VoIP Calls ──
            foreach (var v in ctx.VoipCalls)
                _entries.Add(MakeEntry(DateTime.Now, "VoIP", v.FromIP ?? v.From, v.ToIP ?? v.To,
                    $"{v.From} → {v.To} [{v.CallState}]"));

            // ── HTTP Transactions ──
            foreach (var h in ctx.HttpTransactions)
                _entries.Add(MakeEntry(h.Timestamp, "HTTP", h.SourceIp, h.DestinationIp,
                    $"{h.Method} {h.Uri} → {h.StatusCode} [{h.Host}]"));

            // ── TLS Certificates ──
            foreach (var t in ctx.TlsCertificates)
                _entries.Add(MakeEntry(t.NotBefore, "TLS", "", t.ServerIp,
                    $"Subject: {t.Subject} / Issuer: {t.Issuer} {(t.IsSuspicious ? "⚠SUSPICIOUS" : "")}"));

            // ── JA3 Fingerprints ──
            foreach (var j in ctx.Ja3Fingerprints)
                _entries.Add(MakeEntry(DateTime.Now, "JA3", j.Source, j.Destination,
                    $"JA3: {(j as dynamic)?.Ja3Hash ?? "N/A"}"));

            // ── Alerts (PayloadAlerts) ──
            foreach (var a in ctx.PayloadAlerts)
                _entries.Add(MakeEntry(a.Timestamp, "Alert", a.SourceIp, a.DestinationIp,
                    $"[{a.Severity}] {a.AlertType}: {Truncate(a.Details, 80)}"));

            // ── Beacons ──
            foreach (var b in ctx.BeaconResults)
                _entries.Add(MakeEntry(DateTime.Now, "Beacon", "", b.ProbableC2Server,
                    $"Score: {b.BeaconScore:F1} | Connections: {b.ConnectionCount} | Interval: {b.MeanIntervalSeconds:F1}s | Jitter: {b.JitterRatio:F3}"));

            // ── DHCP ──
            foreach (var d in ctx.DhcpLeases)
                _entries.Add(MakeEntry(d.Timestamp, "DHCP", d.ServerIp, d.AssignedIp,
                    $"Client: {d.ClientMac} / Hostname: {d.Hostname} ({d.VendorClass})"));

            // ── SSH ──
            foreach (var s in ctx.SshFingerprints)
                _entries.Add(MakeEntry(DateTime.Now, "SSH", s.ClientIp, s.ServerIp,
                    $"{s.KeyType} / {s.Banner ?? s.SoftwareVersion}"));

            // ── DNS Exfiltration ──
            foreach (var e in ctx.DnsExfilAlerts)
                _entries.Add(MakeEntry(DateTime.Now, "DNS Exfil", e.SourceIp, e.DestinationIp,
                    $"[{e.Severity}] Domain: {e.Domain} Query: {Truncate(e.Query, 60)}"));

            RefreshGrid();
        }

        private static TimelineEntry MakeEntry(DateTime time, string type, string src, string dst, string summary)
        {
            return new TimelineEntry
            {
                Time = time == default ? DateTime.Now : time,
                Type = type,
                Source = src ?? "",
                Destination = dst ?? "",
                Summary = summary ?? ""
            };
        }

        private static string Truncate(string value, int maxLen)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Length <= maxLen ? value : value.Substring(0, maxLen) + "…";
        }

        private void RefreshGrid()
        {
            _timelineGrid.SuspendLayout();
            _timelineGrid.Rows.Clear();

            foreach (var e in _entries.OrderByDescending(e => e.Time))
            {
                _timelineGrid.Rows.Add(
                    e.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                    e.Type,
                    e.Source,
                    e.Destination,
                    e.Summary
                );
            }

            _timelineGrid.ResumeLayout();
        }

        /// <summary>
        /// Color-code rows by event type using the Catppuccin palette.
        /// </summary>
        private void TimelineGrid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (_timelineGrid.Rows[e.RowIndex].DataBoundItem != null) return;

            var typeCell = _timelineGrid.Rows[e.RowIndex].Cells[1];
            var typeVal = typeCell.Value?.ToString() ?? "";

            _timelineGrid.Rows[e.RowIndex].DefaultCellStyle.BackColor = typeVal switch
            {
                "Password" => Color.FromArgb(0x45, 0x1E, 0x1E),    // dark red
                "Hash" => Color.FromArgb(0x3B, 0x2E, 0x1A),         // dark amber
                "Connection" => Color.FromArgb(0x1E, 0x2E, 0x45),   // dark blue
                "File" => Color.FromArgb(0x1E, 0x3B, 0x2E),          // dark green
                "DNS" => Color.FromArgb(0x2E, 0x1E, 0x3B),          // dark purple
                "VoIP" => Color.FromArgb(0x3B, 0x1E, 0x2E),         // dark pink
                "HTTP" => Color.FromArgb(0x2E, 0x3B, 0x1E),         // dark lime
                "TLS" => Color.FromArgb(0x1E, 0x35, 0x3B),          // dark teal
                "JA3" => Color.FromArgb(0x35, 0x2E, 0x1E),          // dark orange
                "Alert" => Color.FromArgb(0x45, 0x15, 0x15),        // bright dark red
                "Beacon" => Color.FromArgb(0x45, 0x22, 0x0A),       // dark blood orange
                "DHCP" => Color.FromArgb(0x22, 0x3B, 0x3B),         // dark cyan
                "SSH" => Color.FromArgb(0x2E, 0x2E, 0x45),          // dark indigo
                "DNS Exfil" => Color.FromArgb(0x45, 0x0A, 0x22),    // dark magenta
                _ => Color.FromArgb(0x25, 0x25, 0x40)               // default panel bg
            };

            _timelineGrid.Rows[e.RowIndex].DefaultCellStyle.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
        }

        private static void StyleGrid(DataGridView g)
        {
            g.DefaultCellStyle.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
            g.DefaultCellStyle.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
            g.DefaultCellStyle.SelectionBackColor = Color.FromArgb(0x45, 0x47, 0x5A);
            g.DefaultCellStyle.SelectionForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
            g.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(0x45, 0x47, 0x5A);
            g.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
            g.EnableHeadersVisualStyles = false;
            g.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize;
        }

        private void ExportCsv(object sender, EventArgs e)
        {
            if (_entries.Count == 0)
            {
                MessageBox.Show("No timeline entries to export.", "Timeline Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (var dialog = new SaveFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                DefaultExt = "csv",
                FileName = $"BruteShark_Timeline_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            })
            {
                if (dialog.ShowDialog() != DialogResult.OK) return;

                try
                {
                    using (var sw = new StreamWriter(dialog.FileName))
                    {
                        sw.WriteLine("Time,Type,Source,Destination,Summary");
                        foreach (var e2 in _entries.OrderByDescending(e => e.Time))
                        {
                            sw.WriteLine($"\"{e2.Time:yyyy-MM-dd HH:mm:ss}\",\"{e2.Type}\",\"{EscapeCsv(e2.Source)}\",\"{EscapeCsv(e2.Destination)}\",\"{EscapeCsv(e2.Summary)}\"");
                        }
                    }
                    MessageBox.Show($"Timeline exported: {dialog.FileName}", "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private static string EscapeCsv(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
                return value.Replace("\"", "\"\"");
            return value;
        }
    }
}
