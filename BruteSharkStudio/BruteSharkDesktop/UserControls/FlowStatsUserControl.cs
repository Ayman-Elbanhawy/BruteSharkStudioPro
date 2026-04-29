using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    /// <summary>
    /// NetFlow-style traffic statistics — protocol distribution, top talkers, flow summaries.
    /// </summary>
    public class FlowStatsUserControl : UserControl
    {
        private DataGridView _protocolGrid;
        private DataGridView _talkersGrid;
        private Label _flowSummaryLabel;
        private Label _protocolLabel;
        private Label _talkersLabel;
        private Button _exportButton;
        private FlowStatsData _lastData;

        private struct FlowStatsData
        {
            public List<ProtocolRow> Protocols;
            public List<TalkerRow> Talkers;
            public int TotalFlows;
            public int UniqueSources;
            public int UniqueDestinations;
            public long TotalPackets;
            public long TotalBytes;
        }

        private struct ProtocolRow
        {
            public string Name;
            public int PacketCount;
            public long ByteCount;
            public double Percentage;
        }

        private struct TalkerRow
        {
            public string Source;
            public string Destination;
            public int PacketCount;
            public long ByteCount;
        }

        // Catppuccin palette for protocol colors
        private static readonly Color[] ProtocolColors = new[]
        {
            Color.FromArgb(0x89, 0xB4, 0xFA), // blue
            Color.FromArgb(0xA6, 0xE3, 0xA1), // green
            Color.FromArgb(0xFA, 0xB3, 0x87), // peach
            Color.FromArgb(0xCB, 0xA6, 0xF7), // mauve
            Color.FromArgb(0xF3, 0x8B, 0xA8), // pink
            Color.FromArgb(0x94, 0xE2, 0xD5), // teal
            Color.FromArgb(0xFA, 0xE3, 0x72), // yellow
            Color.FromArgb(0xB4, 0xBE, 0xFE), // lavender
            Color.FromArgb(0xBA, 0xB8, 0xC2), // subtitle
            Color.FromArgb(0x74, 0xC7, 0xEC)  // sapphire
        };

        public FlowStatsUserControl()
        {
            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.Dock = DockStyle.Fill;

            // ── Top panel ──
            var topPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 40,
                BackColor = Color.FromArgb(0x25, 0x25, 0x40)
            };

            var titleLabel = new Label
            {
                Text = "Flow Statistics",
                Location = new Point(10, 10),
                AutoSize = true,
                ForeColor = Color.FromArgb(0x89, 0xB4, 0xFA),
                BackColor = Color.FromArgb(0x25, 0x25, 0x40),
                Font = new Font("Segoe UI", 11f, FontStyle.Bold)
            };

            _exportButton = new Button
            {
                Text = "Export CSV",
                Location = new Point(200, 6),
                Size = new Size(120, 28),
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

            // ── Flow Summary label (top area) ──
            _flowSummaryLabel = new Label
            {
                Dock = DockStyle.Top,
                Height = 36,
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Padding(12, 8, 0, 0),
                Text = "No data loaded."
            };

            // ── Protocol Distribution section ──
            _protocolLabel = new Label
            {
                Text = "Protocol Distribution",
                Location = new Point(12, 90),
                AutoSize = true,
                ForeColor = Color.FromArgb(0xA6, 0xE3, 0xA1),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };

            _protocolGrid = new DataGridView
            {
                Location = new Point(12, 112),
                Width = 500,
                Height = 250,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Bottom | AnchorStyles.Right,
                BackgroundColor = Color.FromArgb(0x25, 0x25, 0x40),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                GridColor = Color.FromArgb(0x45, 0x47, 0x5A),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCellsExceptHeader,
                ScrollBars = ScrollBars.Both
            };
            _protocolGrid.Columns.Add("Protocol", "Protocol");
            _protocolGrid.Columns.Add("Packets", "Packets");
            _protocolGrid.Columns.Add("Bytes", "Bytes");
            _protocolGrid.Columns.Add("Pct", "%");
            _protocolGrid.Columns["Protocol"].MinimumWidth = 80;
            _protocolGrid.Columns["Packets"].MinimumWidth = 70;
            _protocolGrid.Columns["Bytes"].MinimumWidth = 70;
            _protocolGrid.Columns["Pct"].MinimumWidth = 50;
            _protocolGrid.CellFormatting += ProtocolGrid_CellFormatting;
            StyleGrid(_protocolGrid);

            // ── Top Talkers grid ──
            _talkersLabel = new Label
            {
                Text = "Top Talkers",
                Location = new Point(12, 348),
                AutoSize = true,
                ForeColor = Color.FromArgb(0xFA, 0xB3, 0x87),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };

            _talkersGrid = new DataGridView
            {
                Location = new Point(12, 370),
                Width = 800,
                Height = 250,
                Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Bottom | AnchorStyles.Right,
                BackgroundColor = Color.FromArgb(0x25, 0x25, 0x40),
                ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4),
                GridColor = Color.FromArgb(0x45, 0x47, 0x5A),
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCellsExceptHeader,
                ScrollBars = ScrollBars.Both
            };
            _talkersGrid.Columns.Add("Source", "Source IP");
            _talkersGrid.Columns.Add("Destination", "Dest. IP");
            _talkersGrid.Columns.Add("Packets", "Packets");
            _talkersGrid.Columns.Add("Bytes", "Bytes");
            _talkersGrid.Columns["Source"].MinimumWidth = 120;
            _talkersGrid.Columns["Destination"].MinimumWidth = 120;
            _talkersGrid.Columns["Packets"].MinimumWidth = 70;
            _talkersGrid.Columns["Bytes"].MinimumWidth = 70;
            StyleGrid(_talkersGrid);

            // Put talkers label above the grid
            _talkersLabel = new Label
            {
                Text = "Top Talkers",
                Location = new Point(12, 348),
                AutoSize = true,
                ForeColor = Color.FromArgb(0xFA, 0xB3, 0x87),
                BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E),
                Font = new Font("Segoe UI", 10f, FontStyle.Bold)
            };

            // Scrollable container for everything
            var scrollPanel = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E) };
            scrollPanel.Controls.Add(_talkersGrid);
            scrollPanel.Controls.Add(_talkersLabel);
            scrollPanel.Controls.Add(_protocolGrid);
            scrollPanel.Controls.Add(_protocolLabel);
            scrollPanel.Controls.Add(_flowSummaryLabel);
            this.Controls.Add(scrollPanel);
            this.Controls.Add(topPanel);
        }

        /// <summary>
        /// Load flow statistics from the network context.
        /// </summary>
        public void LoadFromContext(CommonUi.NetworkContext ctx)
        {
            if (ctx == null)
            {
                _flowSummaryLabel.Text = "No data loaded.";
                _protocolGrid.Rows.Clear();
                _talkersGrid.Rows.Clear();
                return;
            }

            // ── Protocol Distribution ──
            var protocolCounts = new Dictionary<string, (int Packets, long Bytes)>();

            // Count protocols from connections, HTTP, TLS, SSH, DHCP
            void AddProto(string proto, int pktCount = 1, long byteCount = 0)
            {
                if (string.IsNullOrEmpty(proto)) proto = "Unknown";
                if (!protocolCounts.ContainsKey(proto))
                    protocolCounts[proto] = (0, 0);
                var cur = protocolCounts[proto];
                protocolCounts[proto] = (cur.Packets + pktCount, cur.Bytes + byteCount);
            }

            foreach (var c in ctx.Connections)
                AddProto(c.Protocol ?? "TCP", 1, 0);

            foreach (var h in ctx.HttpTransactions)
                AddProto("HTTP", 1, 0);

            foreach (var t in ctx.TlsCertificates)
                AddProto("TLS", 1, 0);

            foreach (var s in ctx.SshFingerprints)
                AddProto("SSH", 1, 0);

            foreach (var d in ctx.DhcpLeases)
                AddProto("DHCP", 1, 0);

            foreach (var p in ctx.PayloadAlerts)
                AddProto(p.Protocol ?? "Alert", 1, 0);

            foreach (var b in ctx.BeaconResults)
                AddProto("Beacon", 1, 0);

            foreach (var j in ctx.Ja3Fingerprints)
                AddProto("TLS/JA3", 1, 0);

            foreach (var v in ctx.VoipCalls)
                AddProto("VoIP/SIP", 1, 0);

            foreach (var d in ctx.DnsMappings)
                AddProto("DNS", 1, 0);

            long totalBytes = protocolCounts.Values.Sum(v => v.Bytes);
            int totalPackets = protocolCounts.Values.Sum(v => v.Packets);

            var protoRows = new List<ProtocolRow>();
            _protocolGrid.Rows.Clear();
            foreach (var kvp in protocolCounts.OrderByDescending(k => k.Value.Packets))
            {
                double pct = totalPackets > 0 ? (double)kvp.Value.Packets / totalPackets * 100 : 0;
                _protocolGrid.Rows.Add(kvp.Key, kvp.Value.Packets, kvp.Value.Bytes, $"{pct:F1}");
                protoRows.Add(new ProtocolRow
                {
                    Name = kvp.Key,
                    PacketCount = kvp.Value.Packets,
                    ByteCount = kvp.Value.Bytes,
                    Percentage = pct
                });
            }

            // ── Top Talkers from connections ──
            var talkerDict = new Dictionary<string, (int Packets, long Bytes)>();
            foreach (var c in ctx.Connections)
            {
                var key = $"{c.Source}→{c.Destination}";
                if (!talkerDict.ContainsKey(key))
                    talkerDict[key] = (0, 0);
                var cur = talkerDict[key];
                talkerDict[key] = (cur.Packets + 1, cur.Bytes + 0);
            }

            // Also extract talker-like info from HTTP transactions
            foreach (var h in ctx.HttpTransactions)
            {
                var key = $"{h.SourceIp}→{h.DestinationIp}";
                if (!talkerDict.ContainsKey(key))
                    talkerDict[key] = (0, 0);
                var cur = talkerDict[key];
                talkerDict[key] = (cur.Packets + 1, cur.Bytes + 0);
            }

            var talkerRows = new List<TalkerRow>();
            _talkersGrid.Rows.Clear();
            foreach (var kvp in talkerDict.OrderByDescending(k => k.Value.Packets).Take(30))
            {
                var parts = kvp.Key.Split('→');
                var src = parts.Length > 0 ? parts[0].Trim() : "";
                var dst = parts.Length > 1 ? parts[1].Trim() : "";
                _talkersGrid.Rows.Add(src, dst, kvp.Value.Packets, kvp.Value.Bytes);
                talkerRows.Add(new TalkerRow
                {
                    Source = src,
                    Destination = dst,
                    PacketCount = kvp.Value.Packets,
                    ByteCount = kvp.Value.Bytes
                });
            }

            // ── Flow Summary ──
            var uniqueSrcs = new HashSet<string>();
            var uniqueDsts = new HashSet<string>();

            foreach (var c in ctx.Connections)
            {
                if (!string.IsNullOrEmpty(c.Source)) uniqueSrcs.Add(c.Source);
                if (!string.IsNullOrEmpty(c.Destination)) uniqueDsts.Add(c.Destination);
            }
            foreach (var h in ctx.HttpTransactions)
            {
                if (!string.IsNullOrEmpty(h.SourceIp)) uniqueSrcs.Add(h.SourceIp);
                if (!string.IsNullOrEmpty(h.DestinationIp)) uniqueDsts.Add(h.DestinationIp);
            }
            foreach (var t in ctx.TlsCertificates)
                if (!string.IsNullOrEmpty(t.ServerIp)) uniqueDsts.Add(t.ServerIp);
            foreach (var s in ctx.SshFingerprints)
            {
                if (!string.IsNullOrEmpty(s.ClientIp)) uniqueSrcs.Add(s.ClientIp);
                if (!string.IsNullOrEmpty(s.ServerIp)) uniqueDsts.Add(s.ServerIp);
            }

            int totalFlows = ctx.Connections.Count;
            long totalDataBytes = 0;
            foreach (var f in ctx.NetworkFiles) totalDataBytes += f.FileSize;

            _flowSummaryLabel.Text =
                $"Total Flows: {totalFlows}  |  " +
                $"Unique Sources: {uniqueSrcs.Count}  |  " +
                $"Unique Destinations: {uniqueDsts.Count}  |  " +
                $"Total Items: {totalPackets}  |  " +
                $"Data Size: {FormatBytes(totalDataBytes)}";

            _lastData = new FlowStatsData
            {
                Protocols = protoRows,
                Talkers = talkerRows,
                TotalFlows = totalFlows,
                UniqueSources = uniqueSrcs.Count,
                UniqueDestinations = uniqueDsts.Count,
                TotalPackets = totalPackets,
                TotalBytes = totalDataBytes
            };
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1_073_741_824) return $"{bytes / 1_073_741_824.0:F1} GB";
            if (bytes >= 1_048_576) return $"{bytes / 1_048_576.0:F1} MB";
            if (bytes >= 1_024) return $"{bytes / 1_024.0:F1} KB";
            return $"{bytes} B";
        }

        /// <summary>
        /// Load flow statistics from the FlowAggregationEngine (v2.3 — deep integration).
        /// </summary>
        public void LoadFromEngine(PcapAnalyzer.FlowAggregationEngine engine)
        {
            if (engine == null) { _flowSummaryLabel.Text = "No engine data."; return; }

            var stats = engine.GetStatistics();
            var flows = engine.GetTopFlows(20);
            var talkers = engine.GetTopTalkers(20);
            var protoDist = engine.GetProtocolDistribution();

            // Protocol Distribution
            _protocolGrid.Rows.Clear();
            long totalPackets = protoDist.Values.Sum();
            foreach (var kvp in protoDist.OrderByDescending(k => k.Value))
            {
                double pct = totalPackets > 0 ? (double)kvp.Value / totalPackets * 100 : 0;
                _protocolGrid.Rows.Add(kvp.Key, kvp.Value, "—", $"{pct:F1}");
            }

            // Top Talkers from engine
            _talkersGrid.Rows.Clear();
            foreach (var t in talkers)
                _talkersGrid.Rows.Add(t.IpAddress, "—", t.TotalPackets, $"{t.TotalBytes} B");

            // Flow Summary from real statistics
            _flowSummaryLabel.Text =
                $"Total Flows: {stats.TotalFlows} | Tcp: {stats.TcpFlows} | Udp: {stats.UdpFlows} | " +
                $"Unique Src: {stats.UniqueSourceIps} | Unique Dst: {stats.UniqueDestIps} | " +
                $"Total: {stats.TotalPackets} pkts, {FormatBytes(stats.TotalBytes)}";
        }

        /// <summary>
        /// Row coloring for protocol distribution grid.
        /// </summary>
        private void ProtocolGrid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (_protocolGrid.Rows[e.RowIndex].DataBoundItem != null) return;

            int colorIndex = e.RowIndex % ProtocolColors.Length;
            _protocolGrid.Rows[e.RowIndex].DefaultCellStyle.BackColor =
                Color.FromArgb(0x25, 0x25, 0x40); // keep consistent
            // Make first column (protocol name) colored
            if (e.ColumnIndex == 0)
            {
                e.CellStyle.ForeColor = ProtocolColors[colorIndex];
            }
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
            if (_lastData.Protocols.Count == 0 && _lastData.Talkers.Count == 0)
            {
                MessageBox.Show("No flow statistics to export.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            using (var dialog = new SaveFileDialog
            {
                Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
                DefaultExt = "csv",
                FileName = $"BruteShark_FlowStats_{DateTime.Now:yyyyMMdd_HHmmss}.csv"
            })
            {
                if (dialog.ShowDialog() != DialogResult.OK) return;

                try
                {
                    using (var sw = new StreamWriter(dialog.FileName))
                    {
                        sw.WriteLine("=== Flow Summary ===");
                        sw.WriteLine($"Total Flows,{_lastData.TotalFlows}");
                        sw.WriteLine($"Unique Sources,{_lastData.UniqueSources}");
                        sw.WriteLine($"Unique Destinations,{_lastData.UniqueDestinations}");
                        sw.WriteLine($"Total Items,{_lastData.TotalPackets}");
                        sw.WriteLine($"Data Size,{_lastData.TotalBytes}");
                        sw.WriteLine();

                        sw.WriteLine("=== Protocol Distribution ===");
                        sw.WriteLine("Protocol,Packets,Bytes,Percentage");
                        foreach (var p in _lastData.Protocols)
                            sw.WriteLine($"\"{p.Name}\",{p.PacketCount},{p.ByteCount},{p.Percentage:F1}");

                        sw.WriteLine();
                        sw.WriteLine("=== Top Talkers ===");
                        sw.WriteLine("Source IP,Dest. IP,Packets,Bytes");
                        foreach (var t in _lastData.Talkers)
                            sw.WriteLine($"\"{t.Source}\",\"{t.Destination}\",{t.PacketCount},{t.ByteCount}");
                    }

                    MessageBox.Show($"Flow statistics exported: {dialog.FileName}", "Export Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
    }
}
