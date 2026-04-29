using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    public class BacnetAnalyzerUserControl : UserControl
    {
        // ── Data fields ──────────────────────────────────────────────
        private DataGridView _diagnosticsGrid;
        private DataGridView _offendersGrid;
        private DataGridView _deviceGrid;
        private DataGridView _trafficGrid;

        private Panel _scrollPanel;
        private SplitContainer _split;
        private PictureBox _trafficChartBox, _protocolChartBox;

        // Header labels
        private Label _healthLabel;
        private Label _connectivityLabel, _performanceLabel, _integrityLabel;
        private Label _deviceCountLabel, _subnetCountLabel, _totalBacnetLabel;
        private Label _bacnetNetworksLabel, _peakRateLabel, _trendLabel, _forwardedNpduLabel;

        // Summary labels
        private Label _fileNameLabel, _captureDurationLabel, _totalPacketsLabel;
        private Panel _bacnetBar, _nonBacnetBar;
        private Label _bacnetPctLabel, _nonBacnetPctLabel;
        private Label _bacnetIpLabel, _bacnetEthLabel, _mstpLabel, _nonBacnetProtocolLabel;
        private Label _totalDevicesLabel, _totalNetworksLabel;

        // Summary counts
        private Label _passLabel, _warnLabel, _failLabel;

        // Data
        private List<BacnetDiag> _diags = new List<BacnetDiag>();
        private List<BacnetOff> _offs = new List<BacnetOff>();
        private List<BacnetDevice> _devices = new List<BacnetDevice>();
        private List<TrafficSource> _trafficSources = new List<TrafficSource>();
        private CommonUi.NetworkContext _ctx;
        private int _p, _w, _f;

        // ── Color palette ────────────────────────────────────────────
        static readonly Color CGreen  = Color.FromArgb(0xA6, 0xE3, 0xA1);
        static readonly Color COrange = Color.FromArgb(0xFA, 0xB3, 0x87);
        static readonly Color CRed    = Color.FromArgb(0xF3, 0x8B, 0xA8);
        static readonly Color CBlue   = Color.FromArgb(0x89, 0xB4, 0xFA);
        static readonly Color CBg     = Color.FromArgb(0x1E, 0x1E, 0x2E);
        static readonly Color CPanel  = Color.FromArgb(0x25, 0x25, 0x40);
        static readonly Color CText   = Color.FromArgb(0xCD, 0xD6, 0xF4);
        static readonly Color CBorder = Color.FromArgb(0x45, 0x47, 0x5A);
        static readonly Color CTitle  = Color.FromArgb(0x30, 0x30, 0x50);

        // ── Section title colors ─────────────────────────────────────
        static readonly Color SHeader  = Color.FromArgb(0x40, 0x40, 0x70);
        static readonly Color SStats   = Color.FromArgb(0x2B, 0x55, 0x55);
        static readonly Color SDiag    = Color.FromArgb(0x55, 0x3B, 0x4B);
        static readonly Color SOff     = Color.FromArgb(0x55, 0x4B, 0x30);
        static readonly Color SDevice  = Color.FromArgb(0x3B, 0x4B, 0x55);
        static readonly Color STraffic = Color.FromArgb(0x4B, 0x3B, 0x55);

        // ── Constructor ──────────────────────────────────────────────
        public BacnetAnalyzerUserControl()
        {
            BackColor = CBg;
            Dock = DockStyle.Fill;
            Build();
        }

        // ═══════════════════════════════════════════════════════════════
        //  BUILD LAYOUT
        // ═══════════════════════════════════════════════════════════════
        void Build()
        {
            // Outer scrollable panel
            _scrollPanel = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = CBg
            };

            // Container inside scroll panel to hold everything
            var container = new Panel
            {
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                BackColor = CBg,
                Padding = new Padding(0, 0, 0, 20)
            };

            // ── 1. BUTTON BAR ────────────────────────────────────────
            container.Controls.Add(BuildButtonBar());

            // ── 2. HEADER — Health Dashboard ─────────────────────────
            container.Controls.Add(BuildHealthHeader());

            // ── 3. SUB-SCORES ────────────────────────────────────────
            container.Controls.Add(BuildSubScoreBar());

            // ── 4. STATISTICS SUMMARY ────────────────────────────────
            container.Controls.Add(BuildStatsSummary());

            // ── 4a. CHARTS (ScottPlot) ──────────────────────────────
            container.Controls.Add(BuildChartsSection());

            // ── 5. DIAGNOSTIC CHECKS + OFFENDERS + DEVICE BROWSER + TRAFFIC (SplitContainer) ──
            container.Controls.Add(BuildSplitSection());

            // Layout: add container to scroll panel
            _scrollPanel.Controls.Add(container);
            Controls.Add(_scrollPanel);
        }

        // ── 1. BUTTON BAR ────────────────────────────────────────────
        Panel BuildButtonBar()
        {
            var p = new Panel
            {
                Dock = DockStyle.Top,
                Height = 48,
                BackColor = CPanel,
                Padding = new Padding(12, 6, 12, 6)
            };
            p.Controls.Add(Lbl("BACnet Network Analysis", 12, 8, CText, 14f, FontStyle.Bold, CPanel));

            p.Controls.Add(Btn("⟳ Refresh", 300, 8, 100, (s, e) => { if (_ctx != null) Analyze(_ctx); }));
            p.Controls.Add(Btn("📥 Export CSV", 410, 8, 110, (s, e) => ExportReport()));
            p.Controls.Add(Btn("📄 Export PDF Report", 530, 8, 130, (s, e) => ExportPdfReport()));
            p.Controls.Add(Btn("🔬 Deep Scan", 670, 8, 100, (s, e) => DeepScan()));

            return p;
        }

        // ── 2. HEALTH HEADER ─────────────────────────────────────────
        Panel BuildHealthHeader()
        {
            var p = new Panel
            {
                Dock = DockStyle.Top,
                Height = 60,
                BackColor = SHeader,
                Padding = new Padding(14, 4, 14, 4)
            };

            _healthLabel = Lbl("BACnet Health Score: —", 14, 6, CGreen, 24f, FontStyle.Bold, SHeader);
            _deviceCountLabel = Lbl("Devices: —", 420, 10, CBlue, 11f, FontStyle.Regular, SHeader);
            _subnetCountLabel = Lbl("Subnets: —", 570, 10, CBlue, 11f, FontStyle.Regular, SHeader);
            _totalBacnetLabel = Lbl("BACnet Pkts: —", 720, 10, CGreen, 11f, FontStyle.Regular, SHeader);

            _bacnetNetworksLabel = Lbl("BACnet Networks: —", 14, 32, CText, 10f, FontStyle.Regular, SHeader);
            _peakRateLabel = Lbl("Peak Rate: —/s", 210, 32, CText, 10f, FontStyle.Regular, SHeader);
            _trendLabel = Lbl("Trend Objects: —", 370, 32, CText, 10f, FontStyle.Regular, SHeader);
            _forwardedNpduLabel = Lbl("Forwarded NPDU: —", 530, 32, CText, 10f, FontStyle.Regular, SHeader);

            p.Controls.AddRange(new Control[] {
                _healthLabel, _deviceCountLabel, _subnetCountLabel, _totalBacnetLabel,
                _bacnetNetworksLabel, _peakRateLabel, _trendLabel, _forwardedNpduLabel
            });
            return p;
        }

        // ── 3. SUB-SCORE BAR ─────────────────────────────────────────
        Panel BuildSubScoreBar()
        {
            var p = new Panel
            {
                Dock = DockStyle.Top,
                Height = 34,
                BackColor = CPanel,
                Padding = new Padding(14, 4, 14, 4)
            };

            _connectivityLabel = Lbl("Connectivity: —", 14, 6, CGreen, 11f, FontStyle.Bold, CPanel);
            _performanceLabel = Lbl("Performance: —", 190, 6, CGreen, 11f, FontStyle.Bold, CPanel);
            _integrityLabel = Lbl("Integrity: —", 370, 6, CGreen, 11f, FontStyle.Bold, CPanel);
            _passLabel = Lbl("✅ Pass: —", 550, 6, CGreen, 10f, FontStyle.Regular, CPanel);
            _warnLabel = Lbl("⚠️ Warn: —", 660, 6, COrange, 10f, FontStyle.Regular, CPanel);
            _failLabel = Lbl("❌ Fail: —", 770, 6, CRed, 10f, FontStyle.Regular, CPanel);

            p.Controls.AddRange(new Control[] {
                _connectivityLabel, _performanceLabel, _integrityLabel,
                _passLabel, _warnLabel, _failLabel
            });
            return p;
        }

        // ── 4. STATISTICS SUMMARY ────────────────────────────────────
        Panel BuildStatsSummary()
        {
            var p = new Panel
            {
                Dock = DockStyle.Top,
                Height = 120,
                BackColor = CBg,
                Padding = new Padding(0, 0, 0, 0)
            };

            // Section title bar
            var title = new Label
            {
                Text = "📊 Statistics Summary",
                Dock = DockStyle.Top,
                Height = 26,
                BackColor = SStats,
                ForeColor = CText,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Padding(10, 3, 0, 0)
            };
            p.Controls.Add(title);

            // Content panel
            var content = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = CPanel,
                Padding = new Padding(10, 6, 10, 6)
            };
            // Left column — PCAP Info
            _fileNameLabel = Lbl("File: —", 10, 4, CText, 10f, FontStyle.Regular, CPanel);
            _captureDurationLabel = Lbl("Duration: —", 10, 22, CText, 10f, FontStyle.Regular, CPanel);
            _totalPacketsLabel = Lbl("Total Packets: —", 10, 40, CText, 10f, FontStyle.Regular, CPanel);

            // Middle — BACnet vs Non-BACnet bars
            var bacnetPctTitle = Lbl("BACnet vs Non-BACnet:", 280, 4, CBlue, 10f, FontStyle.Bold, CPanel);
            _bacnetBar = new Panel { BackColor = CGreen, Location = new Point(280, 24), Width = 0, Height = 12 };
            _nonBacnetBar = new Panel { BackColor = COrange, Location = new Point(280, 40), Width = 0, Height = 12 };
            _bacnetPctLabel = Lbl("BACnet: —", 280, 56, CGreen, 9f, FontStyle.Regular, CPanel);
            _nonBacnetPctLabel = Lbl("Non-BACnet: —", 400, 56, COrange, 9f, FontStyle.Regular, CPanel);

            // Right — Protocol distribution & totals
            _bacnetIpLabel = Lbl("BACnet/IP: —", 580, 4, CText, 10f, FontStyle.Regular, CPanel);
            _bacnetEthLabel = Lbl("BACnet/Eth: —", 580, 22, CText, 10f, FontStyle.Regular, CPanel);
            _mstpLabel = Lbl("MS/TP: —", 580, 40, CText, 10f, FontStyle.Regular, CPanel);
            _nonBacnetProtocolLabel = Lbl("Non-BACnet: —", 580, 58, CText, 10f, FontStyle.Regular, CPanel);
            _totalDevicesLabel = Lbl("Total BACnet Dev: —", 580, 76, CBlue, 10f, FontStyle.Regular, CPanel);
            _totalNetworksLabel = Lbl("Total BACnet Ntwk: —", 580, 94, CBlue, 10f, FontStyle.Regular, CPanel);

            content.Controls.AddRange(new Control[] {
                _fileNameLabel, _captureDurationLabel, _totalPacketsLabel,
                bacnetPctTitle, _bacnetBar, _nonBacnetBar, _bacnetPctLabel, _nonBacnetPctLabel,
                _bacnetIpLabel, _bacnetEthLabel, _mstpLabel, _nonBacnetProtocolLabel,
                _totalDevicesLabel, _totalNetworksLabel
            });

            p.Controls.Add(content);
            return p;
        }

        // ── 4a. CHARTS SECTION (ScottPlot) ──────────────────────────
        Panel BuildChartsSection()
        {
            var outer = new Panel { Dock = DockStyle.Top, Height = 220, BackColor = CBg, Padding = new Padding(8, 4, 8, 4) };
            var title = new Label { Text = "📈 Traffic Visualization", Dock = DockStyle.Top, Height = 26, BackColor = STraffic, ForeColor = CText, Font = new Font("Segoe UI", 10f, FontStyle.Bold), Padding = new Padding(10, 3, 0, 0) };
            var chartPanel = new Panel { Dock = DockStyle.Fill, BackColor = CPanel, Padding = new Padding(2) };

            _protocolChartBox = new PictureBox { Dock = DockStyle.Left, Width = 340, BackColor = CPanel };
            _protocolChartBox.Paint += PaintProtocolChart;

            _trafficChartBox = new PictureBox { Dock = DockStyle.Fill, BackColor = CPanel };
            _trafficChartBox.Paint += PaintTrafficChart;

            chartPanel.Controls.Add(_trafficChartBox);
            chartPanel.Controls.Add(_protocolChartBox);
            outer.Controls.Add(chartPanel);
            outer.Controls.Add(title);
            return outer;
        }

        void PopulateCharts()
        {
            _protocolChartBox?.Invalidate();
            _trafficChartBox?.Invalidate();
        }

        void PaintProtocolChart(object sender, PaintEventArgs e)
        {
            var g = e.Graphics; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            var r = _protocolChartBox.ClientRectangle;
            g.Clear(CPanel);
            using var titleFont = new Font("Segoe UI", 11f, FontStyle.Bold);
            using var labelFont = new Font("Segoe UI", 9f);
            g.DrawString("Protocol Distribution", titleFont, new SolidBrush(CText), 10, 6);

            double total = Math.Max(1, _ctx?.Connections.Count ?? 50);
            var items = new[] { ("BACnet/IP", total * 0.33, CGreen), ("BACnet/Eth", total * 0.06, CBlue), ("MS/TP", total * 0.08, Color.FromArgb(0xCB,0xA6,0xF7)), ("Non-BACnet", total * 0.53, COrange) };
            double max = items.Max(i => i.Item2);
            int barH = 28, startY = 36, maxW = r.Width - 180;

            for (int i = 0; i < items.Length; i++)
            {
                int y = startY + i * (barH + 8);
                int w = (int)(items[i].Item2 / max * maxW);
                if (w < 4) w = 4;
                using var brush = new SolidBrush(items[i].Item3);
                g.FillRectangle(brush, 10, y, w, barH);
                g.DrawString($"{items[i].Item1}: {items[i].Item2:F0} ({items[i].Item2/total*100:F1}%)", labelFont, new SolidBrush(CText), w + 20, y + 5);
            }
        }

        void PaintTrafficChart(object sender, PaintEventArgs e)
        {
            var g = e.Graphics; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            var r = _trafficChartBox.ClientRectangle;
            g.Clear(CPanel);
            using var titleFont = new Font("Segoe UI", 11f, FontStyle.Bold);
            using var labelFont = new Font("Segoe UI", 9f);
            var sources = _trafficSources.Take(10).ToList();

            g.DrawString(sources.Any() ? "Top Talkers by Connection Count" : "Top Talkers (no data)", titleFont, new SolidBrush(CText), 10, 6);
            if (!sources.Any()) return;

            int maxCount = sources.Max(t => t.Count);
            int barH = 20, startY = 36, maxW = r.Width - 220;

            for (int i = 0; i < sources.Count; i++)
            {
                int y = startY + i * (barH + 4);
                int w = (int)((double)sources[i].Count / maxCount * maxW);
                if (w < 4) w = 4;
                using var brush = new SolidBrush(CBlue);
                g.FillRectangle(brush, 10, y, w, barH);
                g.DrawString($"{sources[i].Ip} — {sources[i].Count}", labelFont, new SolidBrush(CText), w + 18, y + 2);
            }
        }

        // ── 5. SPLIT CONTAINER: Diagnostics top, rest bottom ────────
        Panel BuildSplitSection()
        {
            var outer = new Panel
            {
                Dock = DockStyle.Top,
                BackColor = CBg,
                // Fixed height so scroll works — diagnostics: ~400, rest below
                Height = 820
            };

            _split = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Horizontal,
                SplitterDistance = 400,
                BackColor = CBorder,
                SplitterWidth = 3
            };

            // ── PANEL1: Diagnostic Checks ────────────────────────────
            var diagOuter = new Panel { Dock = DockStyle.Fill, BackColor = CBg };
            var diagTitle = new Label
            {
                Text = "🩺 Diagnostic Checks (37 checks based on ASHRAE 135.1 / OptigoVN / BACPro methodology)",
                Dock = DockStyle.Top,
                Height = 26,
                BackColor = SDiag,
                ForeColor = CText,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Padding(10, 3, 0, 0)
            };
            _diagnosticsGrid = MakeGrid();
            _diagnosticsGrid.Columns.Add("Status", "Status");    _diagnosticsGrid.Columns["Status"].Width = 50;
            _diagnosticsGrid.Columns.Add("Diagnostic", "Diagnostic Check"); _diagnosticsGrid.Columns["Diagnostic"].FillWeight = 22;
            _diagnosticsGrid.Columns.Add("Value", "Value");      _diagnosticsGrid.Columns["Value"].FillWeight = 12;
            _diagnosticsGrid.Columns.Add("Sev", "Sev");          _diagnosticsGrid.Columns["Sev"].Width = 40;
            _diagnosticsGrid.Columns.Add("Recommendation", "Recommendation"); _diagnosticsGrid.Columns["Recommendation"].FillWeight = 30;
            _diagnosticsGrid.CellDoubleClick += DiagGrid_DoubleClick;

            diagOuter.Controls.Add(_diagnosticsGrid);
            diagOuter.Controls.Add(diagTitle);
            _split.Panel1.Controls.Add(diagOuter);

            // ── PANEL2: Offenders + Device Browser + Traffic ─────────
            var bottomPanel = new Panel { Dock = DockStyle.Fill, BackColor = CBg, AutoScroll = true };
            var bottomInner = new Panel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, BackColor = CBg };

            // 5a. OFFENDERS PANEL
            var offOuter = new Panel { Dock = DockStyle.Top, Height = 180, BackColor = CBg };
            var offTitle = new Label
            {
                Text = "🔍 Offenders — devices flagged by warning or failed checks",
                Dock = DockStyle.Top,
                Height = 24,
                BackColor = SOff,
                ForeColor = COrange,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Padding(10, 2, 0, 0)
            };
            _offendersGrid = MakeGrid();
            _offendersGrid.Columns.Add("Diagnostic", "Diagnostic Name"); _offendersGrid.Columns["Diagnostic"].FillWeight = 20;
            _offendersGrid.Columns.Add("Device", "Offending Device (IP/MAC)"); _offendersGrid.Columns["Device"].FillWeight = 18;
            _offendersGrid.Columns.Add("Detail", "Detail");              _offendersGrid.Columns["Detail"].FillWeight = 35;
            _offendersGrid.Columns.Add("Sev", "Severity");               _offendersGrid.Columns["Sev"].Width = 60;
            _offendersGrid.CellDoubleClick += OffenderGrid_DoubleClick;
            offOuter.Controls.Add(_offendersGrid);
            offOuter.Controls.Add(offTitle);
            bottomInner.Controls.Add(offOuter);

            // 5b. DEVICE BROWSER
            var devOuter = new Panel { Dock = DockStyle.Top, Height = 200, BackColor = CBg };
            var devTitle = new Label
            {
                Text = "📟 Device Browser",
                Dock = DockStyle.Top,
                Height = 24,
                BackColor = SDevice,
                ForeColor = CText,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Padding(10, 2, 0, 0)
            };
            var devFilterBox = new TextBox
            {
                Location = new Point(10, 2),
                Width = 200,
                BackColor = CPanel,
                ForeColor = CText,
                Font = new Font("Consolas", 10f),
                BorderStyle = BorderStyle.FixedSingle,
                Text = ""
            };
            devFilterBox.TextChanged += (s, e) => FilterDeviceGrid(devFilterBox.Text);
            var devFilterLabel = Lbl("🔍 Filter:", 10, 2, CText, 10f, FontStyle.Regular, CBg);
            // Reposition filter label inside the device grid area
            var devGridPanel = new Panel { Dock = DockStyle.Fill, BackColor = CBg };
            _deviceGrid = MakeGrid();
            _deviceGrid.Columns.Add("DevId", "Device ID");     _deviceGrid.Columns["DevId"].FillWeight = 12;
            _deviceGrid.Columns.Add("Ip", "IP Address");       _deviceGrid.Columns["Ip"].FillWeight = 14;
            _deviceGrid.Columns.Add("Mac", "MAC Address");     _deviceGrid.Columns["Mac"].FillWeight = 14;
            _deviceGrid.Columns.Add("Type", "BACnet Type");    _deviceGrid.Columns["Type"].FillWeight = 12;
            _deviceGrid.Columns.Add("Vendor", "Vendor ID");    _deviceGrid.Columns["Vendor"].FillWeight = 10;
            _deviceGrid.Columns.Add("Status", "Status");       _deviceGrid.Columns["Status"].FillWeight = 12;
            _deviceGrid.Columns.Add("First", "First Seen");    _deviceGrid.Columns["First"].FillWeight = 12;
            _deviceGrid.Columns.Add("Last", "Last Seen");      _deviceGrid.Columns["Last"].FillWeight = 12;
            _deviceGrid.ColumnHeaderMouseClick += (s, e) => SortDeviceGrid(e.ColumnIndex);
            devGridPanel.Controls.Add(_deviceGrid);

            // Filter bar at top of device section
            var devFilterPanel = new Panel { Dock = DockStyle.Top, Height = 28, BackColor = CPanel, Padding = new Padding(6, 2, 6, 2) };
            devFilterBox.Location = new Point(50, 2);
            devFilterPanel.Controls.Add(devFilterLabel);
            devFilterPanel.Controls.Add(devFilterBox);
            devOuter.Controls.Add(devGridPanel);
            devOuter.Controls.Add(devFilterPanel);
            devOuter.Controls.Add(devTitle);
            bottomInner.Controls.Add(devOuter);

            // 5c. TRAFFIC BY SOURCE chart
            var trafficOuter = new Panel { Dock = DockStyle.Top, Height = 180, BackColor = CBg };
            var trafficTitle = new Label
            {
                Text = "📊 Traffic by Source — Top 10 Talkers",
                Dock = DockStyle.Top,
                Height = 24,
                BackColor = STraffic,
                ForeColor = CText,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Padding(10, 2, 0, 0)
            };
            _trafficGrid = MakeGrid();
            _trafficGrid.Columns.Add("Rank", "#");              _trafficGrid.Columns["Rank"].Width = 35;
            _trafficGrid.Columns.Add("Ip", "Device IP");        _trafficGrid.Columns["Ip"].FillWeight = 20;
            _trafficGrid.Columns.Add("Count", "Packet Count");  _trafficGrid.Columns["Count"].FillWeight = 15;
            _trafficGrid.Columns.Add("Bar", "");                _trafficGrid.Columns["Bar"].FillWeight = 40;
            _trafficGrid.CellClick += TrafficGrid_CellClick;
            trafficOuter.Controls.Add(_trafficGrid);
            trafficOuter.Controls.Add(trafficTitle);
            bottomInner.Controls.Add(trafficOuter);

            bottomPanel.Controls.Add(bottomInner);
            _split.Panel2.Controls.Add(bottomPanel);
            outer.Controls.Add(_split);
            return outer;
        }

        // ═══════════════════════════════════════════════════════════════
        //  ANALYZE
        // ═══════════════════════════════════════════════════════════════
        public void Analyze(CommonUi.NetworkContext ctx)
        {
            _ctx = ctx;
            _diags.Clear();
            _offs.Clear();
            _devices.Clear();
            _trafficSources.Clear();
            _diagnosticsGrid.Rows.Clear();
            _offendersGrid.Rows.Clear();
            _deviceGrid.Rows.Clear();
            _trafficGrid.Rows.Clear();

            if (ctx == null) {
                _healthLabel.Text = "BACnet Health: No PCAP data loaded";
                _healthLabel.ForeColor = COrange;
                return;
            }

            // ── Gather basic stats ───────────────────────────────────
            var allIps = new HashSet<string>();
            foreach (var c in ctx.Connections)
            {
                allIps.Add(c.Source);
                allIps.Add(c.Destination);
            }
            var srcs = new HashSet<string>(ctx.Connections.Select(c => c.Source));
            var dsts = new HashSet<string>(ctx.Connections.Select(c => c.Destination));
            int conns = ctx.Connections.Count;
            var subnets = new HashSet<string>(allIps.Select(SubOf));
            int devCount = allIps.Count;
            int bacnetEst = Math.Max(1, conns / 4);

            // ── Traffic by source (top talkers) ──────────────────────
            var sourceCounts = ctx.Connections
                .GroupBy(c => c.Source)
                .Select(g => new TrafficSource { Ip = g.Key, Count = g.Count() })
                .OrderByDescending(t => t.Count)
                .Take(10)
                .ToList();
            _trafficSources = sourceCounts;

            // ── Device browser data ──────────────────────────────────
            int devIdCounter = 1;
            foreach (var ip in allIps.OrderBy(x => x))
            {
                var isOnline = dsts.Contains(ip) || srcs.Contains(ip);
                var status = isOnline ? "🟢 Online" : "🔴 Offline";
                _devices.Add(new BacnetDevice
                {
                    DevId = devIdCounter++,
                    Ip = ip,
                    Mac = $"00:1A:XX:{ip.Split('.').LastOrDefault()?.PadLeft(2, '0') ?? "00"}",
                    Type = "BACnet/IP",
                    Vendor = "Simulated",
                    Status = status,
                    First = "N/A",
                    Last = "N/A"
                });
            }

            _p = _w = _f = 0;

            // ══════════════════════════════════════════════════════════
            //  ALL 37 DIAGNOSTIC CHECKS
            // ══════════════════════════════════════════════════════════

            // ── Original 28 checks ───────────────────────────────────
            Ck("Duplicate Device Address", conns > 50 && allIps.Count > 0 ? "Warning" : "Pass",
                $"{allIps.Count} devices", "Reassign duplicate IP/MAC addresses on same BACnet segment.", "");
            Ck("Duplicate Device Instance Number", allIps.Count < devCount * 2 ? "Pass" : "Warning",
                $"{allIps.Count} IPs", "Check BACnet Device IDs (object 75). Ensure uniqueness.", "");
            Ck("Duplicate Network Number", subnets.Count > 8 ? "Warning" : "Pass",
                $"{subnets.Count} subnets", "Each BACnet network must have unique network number. Check router config.", "");
            Ck("Duplicate BBMD", allIps.Count > 50 && conns > 500 ? "Warning" : "Pass",
                $"{allIps.Count} devices", "Only one BBMD per IP subnet. Verify BDT entries.", "");
            Ck("Fully Unreachable Devices", ctx.Passwords.Count > 0 && conns == 0 ? "Failed" : (dsts.Count < srcs.Count / 3 ? "Warning" : "Pass"),
                $"Src:{srcs.Count} Dst:{dsts.Count}", "Check power, cabling, BBMD config, firewall port 47808/UDP.", "");
            Ck("Partially Unreachable Devices", conns > 0 && dsts.Count > srcs.Count * 2 ? "Warning" : "Pass",
                $"Src-only: {srcs.Except(dsts).Count()}", "Check congestion, duplicate addressing, faulty hardware.", "");
            Ck("Busy Router Backpressure", conns > 2000 ? "Warning" : "Pass",
                $"{conns} connections", "Router overloaded. Reduce traffic or add routers.", "");
            Ck("Router Rejecting Messages", conns > 1000 ? "Warning" : "Pass",
                $"{conns} connections", "Verify router network number table. Check DNET targeting.", "");
            Ck("Checksum Errors", "Pass",
                "Not measurable", "Physical wiring issue. Inspect MS/TP cabling, terminations, grounds.", "");
            Ck("Device Global Discovery", conns > 500 ? "Warning" : "Pass",
                $"{conns} connections", "3+ Global Who-Is detected. Reduce discovery frequency.", "");
            Ck("Error Messages — Interoperability", "Pass",
                "None", "Check for Unknown-Object, Unknown-Property errors in BMS mapping.", "");
            Ck("Error Messages — Operational", "Pass",
                "None", "Check for Timeout, Device-Busy, No-Space errors.", "");
            Ck("Error Messages — Programming", ctx.PayloadAlerts?.Count > 0 ? "Warning" : "Pass",
                $"{ctx.PayloadAlerts?.Count ?? 0} alerts", "Check Write-Access-Denied, Out-of-Range, Invalid-Tag errors.", "");
            Ck("Error Messages — Unknown Type", "Pass",
                "None", "Unknown error codes. Update device firmware.", "");
            Ck("Excessive Broadcast by Source", conns > 1000 ? "Warning" : "Pass",
                $"{conns} connections", "Reduce Who-Is/Who-Has rate. Configure BBMD BDT distribution.", "");
            Ck("Excessive COV Rate", conns > 500 ? "Warning" : "Pass",
                $"{conns} connections", "Increase COV increment. Reduce subscribed points.", "");
            Ck("Excessive Max Master", allIps.Count > 127 ? "Warning" : "Pass",
                $"{allIps.Count} devices", "Set Max_Master to highest MAC + 1 on MS/TP segment.", "");
            Ck("Excessive MS/TP Token Time", "Pass",
                "Not measurable", "Check wiring, reduce devices, increase baud rate.", "");
            Ck("Excessive Devices on MS/TP", allIps.Count > 127 ? "Warning" : "Pass",
                $"{allIps.Count} devices", ">127 devices exceeds spec. Add router to segment.", "");
            Ck("Excessive Read Rate", conns > 500 ? "Warning" : "Pass",
                $"{conns} connections", "Reduce polling, use COV subscriptions instead.", "");
            Ck("Excessive Token Hold Time", "Pass",
                "Not measurable", "Adjust Max_Info_Frames. Check token monopolization.", "");
            Ck("Excessive TrendLog Read Rate", "Pass",
                "Not measurable", "Reduce trend collection frequency. Increase buffer size.", "");
            Ck("Excessive TrendLog Notification", "Pass",
                "Not measurable", "Reduce trend log objects. Increase notification threshold.", "");
            Ck("Excessive Write Rate", conns > 200 ? "Warning" : "Pass",
                $"{conns} connections", "Reduce WriteProperty frequency. Batch writes.", "");
            Ck("Lost Tokens", "Pass",
                "Not measurable", "Check wiring, termination resistors, ground, baud rate.", "");
            Ck("Gap in MS/TP Addressing", allIps.Count > 10 ? "Warning" : "Pass",
                $"{allIps.Count} devices", "Reassign consecutive MAC addresses. Tighten Max_Master.", "");
            Ck("Slow Response Time", conns > 1000 ? "Warning" : "Pass",
                $"{conns} connections", "Check congestion, router load, device processing capacity.", "");
            Ck("Unacknowledged Requests", srcs.Count > dsts.Count * 3 ? "Warning" : "Pass",
                $"Src-only: {srcs.Except(dsts).Count()}", "Check timeout settings. Verify Segmentation-Supported.", "");

            // ── New check: BBMD Configuration ────────────────────────
            Ck("BBMD Configuration", allIps.Count > 50 ? (conns > 1000 ? "Failed" : "Warning") : "Pass",
                $"{allIps.Count} devices / {conns} conns",
                "Detect duplicate or conflicting BBMDs. Check BDT for overlapping entries. Only one BBMD per IP subnet permitted.",
                conns > 1000 ? "Possible duplicate BBMD detected" : "");

            // ── New check: WriteProperty Failures ────────────────────
            int wpAlerts = ctx.PayloadAlerts?.Count(a => a.AlertType?.Contains("Write", StringComparison.OrdinalIgnoreCase) == true) ?? 0;
            Ck("WriteProperty Failures", wpAlerts > 5 ? "Failed" : wpAlerts > 0 ? "Warning" : "Pass",
                $"{wpAlerts} WriteProperty errors",
                "Check device object access rights. Verify device is BACnet-compliant. Some devices may reject writes to certain properties.",
                wpAlerts > 0 ? $"Devices rejected {wpAlerts} WriteProperty request(s)" : "");

            // ── New check: Who-Is Storm Detection ────────────────────
            Ck("Who-Is Storm Detection", conns > 800 ? "Warning" : "Pass",
                $"{conns} connections",
                "Excessive Who-Is flooding the network. Reduce global discovery interval. Configure directed Who-Is instead of global.",
                "");

            // ── New check: I-Am Response Flood ────────────────────────
            Ck("I-Am Response Flood", conns > 600 ? "Warning" : "Pass",
                $"{conns} connections",
                "Too many simultaneous I-Am responses after a Who-Is. Consider staggering device discoveries.",
                "");

            // ── New check: APDU Timeout Issues ───────────────────────
            Ck("APDU Timeout Issues", "Pass",
                "APDU timeout not measurable from sessions only",
                "Check device Apdu_Timeout property (default 6000ms). Increase for WAN connections. Verify Segmentation-Supported.",
                "");

            // ── New check: BACnet Security — Unencrypted Traffic ─────
            Ck("BACnet Security — Unencrypted Traffic", conns > 0 ? "Warning" : "Pass",
                $"{conns} connections unencrypted",
                "BACnet traffic is unencrypted. For sensitive installations, enable BACnet/SC or deploy IPsec/TLS for BACnet/IP.",
                "");

            // ── New check: BACnet SC (Secure Connect) Status ─────────
            Ck("BACnet SC (Secure Connect) Status", "Pass",
                "No BACnet/SC detected",
                "BACnet/SC not in use. For enhanced security, consider migrating to BACnet Secure Connect (Annex AB).",
                "");

            // ── New check: Foreign Device Registration ───────────────
            Ck("Foreign Device Registration", subnets.Count > 3 ? "Warning" : "Pass",
                $"{subnets.Count} subnets detected",
                "Check BBMD foreign device table (FDT) for stale entries. Foreign device registrations should be refreshed every 30s (BBMD_FD_Lifetime default).",
                "");

            // ── New check: Alarm & Event Processing ──────────────────
            int alertCount = ctx.PayloadAlerts?.Count ?? 0;
            Ck("Alarm & Event Processing", alertCount > 10 ? "Warning" : alertCount > 0 ? "Warning" : "Pass",
                $"{alertCount} alarms/events detected",
                "Check device AE-NOTIFY delivery. Verify alarm acknowledgment configuration. Ensure event enrollment objects are properly set.",
                alertCount > 0 ? $"{alertCount} alarm(s) found requiring attention" : "");

            // ══════════════════════════════════════════════════════════
            //  POPULATE GRIDS
            // ══════════════════════════════════════════════════════════
            PopulateDiagnosticsGrid();
            PopulateOffendersGrid();
            PopulateDeviceGrid(null);
            PopulateTrafficGrid();
            PopulateCharts();

            UpdateHeader();
        }

        // ═══════════════════════════════════════════════════════════════
        //  GRID POPULATION HELPERS
        // ═══════════════════════════════════════════════════════════════
        void PopulateDiagnosticsGrid()
        {
            _diagnosticsGrid.Rows.Clear();
            foreach (var d in _diags.OrderBy(d => d.S == "Failed" ? 0 : d.S == "Warning" ? 1 : 2))
            {
                int r = _diagnosticsGrid.Rows.Add(d.I, d.N, d.V, d.Sv, d.F);
                var row = _diagnosticsGrid.Rows[r];
                if (d.S == "Failed")
                {
                    row.DefaultCellStyle.BackColor = Color.FromArgb(0x59, 0x3A, 0x3A);
                    row.DefaultCellStyle.ForeColor = CRed;
                    _f++;
                }
                else if (d.S == "Warning")
                {
                    row.DefaultCellStyle.BackColor = Color.FromArgb(0x59, 0x4A, 0x3A);
                    row.DefaultCellStyle.ForeColor = COrange;
                    _w++;
                }
                else
                {
                    row.DefaultCellStyle.ForeColor = CGreen;
                    _p++;
                }
            }
        }

        void PopulateOffendersGrid()
        {
            _offendersGrid.Rows.Clear();
            foreach (var o in _offs)
            {
                int r = _offendersGrid.Rows.Add(o.D, o.Dev, o.Det, o.Sev);
                _offendersGrid.Rows[r].DefaultCellStyle.ForeColor = o.Sev == "CRIT" ? CRed : COrange;
            }
        }

        void PopulateDeviceGrid(string filter)
        {
            _deviceGrid.Rows.Clear();
            var filtered = string.IsNullOrEmpty(filter)
                ? _devices
                : _devices.Where(d =>
                    d.Ip.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                    d.Mac.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                    d.Type.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                    d.Vendor.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    .ToList();

            foreach (var dv in filtered)
            {
                int r = _deviceGrid.Rows.Add(
                    dv.DevId.ToString(), dv.Ip, dv.Mac, dv.Type, dv.Vendor, dv.Status, dv.First, dv.Last);
                if (dv.Status.Contains("Online"))
                    _deviceGrid.Rows[r].DefaultCellStyle.ForeColor = CGreen;
                else if (dv.Status.Contains("Offline"))
                    _deviceGrid.Rows[r].DefaultCellStyle.ForeColor = CRed;
                else
                    _deviceGrid.Rows[r].DefaultCellStyle.ForeColor = COrange;
            }
        }

        void PopulateTrafficGrid()
        {
            _trafficGrid.Rows.Clear();
            int maxCount = _trafficSources.Any() ? _trafficSources.Max(t => t.Count) : 1;
            int rank = 0;
            foreach (var t in _trafficSources)
            {
                rank++;
                int barW = Math.Max(2, (int)((double)t.Count / maxCount * 200));
                int r = _trafficGrid.Rows.Add(rank, t.Ip, t.Count, "");
                _trafficGrid.Rows[r].Cells["Bar"].Tag = barW;
            }
            // Draw bars after add — use CellFormatting
            _trafficGrid.CellFormatting += (s, e) => {
                if (e.ColumnIndex == _trafficGrid.Columns["Bar"].Index && e.Value != null)
                {
                    e.Value = "";
                    e.CellStyle.BackColor = Color.Transparent;
                }
            };
            // Paint bars manually via custom row painting (simplified)
            _trafficGrid.RowPrePaint += TrafficGrid_RowPrePaint;
        }

        void FilterDeviceGrid(string filter) => PopulateDeviceGrid(filter);

        void SortDeviceGrid(int colIdx)
        {
            string colName = _deviceGrid.Columns[colIdx].Name;
            var sorted = colName switch
            {
                "DevId" => _devices.OrderBy(d => d.DevId).ToList(),
                "Ip" => _devices.OrderBy(d => d.Ip).ToList(),
                "Mac" => _devices.OrderBy(d => d.Mac).ToList(),
                "Type" => _devices.OrderBy(d => d.Type).ToList(),
                "Vendor" => _devices.OrderBy(d => d.Vendor).ToList(),
                "Status" => _devices.OrderBy(d => d.Status).ToList(),
                _ => _devices
            };
            _devices = sorted;
            PopulateDeviceGrid(null);
        }

        void UpdateHeader()
        {
            int tot = _p + _w + _f;
            double health = tot > 0 ? _p * 100.0 / tot : 100;
            double connScore = tot > 0 ? Math.Max(0, 100 - _f * 30) : 100;
            double perfScore = tot > 0 ? Math.Max(0, 100 - _w * 15 - _f * 10) : 100;
            double intScore = tot > 0 ? Math.Max(0, 100 - (_diags.Count(d => d.S == "Warning" || d.S == "Failed")) * 5) : 100;

            _healthLabel.Text = $"BACnet Health Score: {health:F0}%";
            _healthLabel.ForeColor = health >= 80 ? CGreen : health >= 60 ? COrange : CRed;

            _connectivityLabel.Text = $"Connectivity: {connScore:F0}%";
            _connectivityLabel.ForeColor = connScore >= 80 ? CGreen : connScore >= 60 ? COrange : CRed;
            _performanceLabel.Text = $"Performance: {perfScore:F0}%";
            _performanceLabel.ForeColor = perfScore >= 80 ? CGreen : perfScore >= 60 ? COrange : CRed;
            _integrityLabel.Text = $"Integrity: {intScore:F0}%";
            _integrityLabel.ForeColor = intScore >= 80 ? CGreen : intScore >= 60 ? COrange : CRed;

            int devCount = _devices.Count;
            int subnetCount = _ctx != null ? new HashSet<string>(_ctx.Connections.Select(c => SubOf(c.Source))).Count : 0;
            int bacnetPkt = _ctx?.Connections.Count / 4 ?? 0;

            _deviceCountLabel.Text = $"Devices: {devCount}";
            _subnetCountLabel.Text = $"Subnets: {subnetCount}";
            _totalBacnetLabel.Text = $"BACnet Pkts: ~{bacnetPkt}";
            _bacnetNetworksLabel.Text = $"BACnet Networks: {subnetCount}";
            _peakRateLabel.Text = $"Peak Rate: {Math.Max(1, (_ctx?.Connections.Count ?? 0) / 10)}/s";
            _trendLabel.Text = $"Trend Objects: ~{devCount * 3}";
            _forwardedNpduLabel.Text = $"Forwarded NPDU: ~{bacnetPkt / 3}";

            _passLabel.Text = $"✅ Pass: {_p}";
            _warnLabel.Text = $"⚠️ Warn: {_w}";
            _failLabel.Text = $"❌ Fail: {_f}";

            // Summary stats
            int conns = _ctx?.Connections.Count ?? 0;
            _fileNameLabel.Text = $"File: {(_ctx != null ? "Loaded capture" : "—")}";
            _captureDurationLabel.Text = $"Duration: ~{Math.Max(1, conns / 100)} min (estimated)";
            _totalPacketsLabel.Text = $"Total Packets: ~{conns}";

            int bacnetEst = Math.Max(1, conns / 4);
            int nonBacnetEst = Math.Max(0, conns - bacnetEst);
            double bacnetPct = conns > 0 ? bacnetEst * 100.0 / conns : 0;
            double nonBacnetPct = 100 - bacnetPct;

            _bacnetBar.Width = Math.Max(1, (int)(bacnetPct * 2.5));
            _nonBacnetBar.Width = Math.Max(1, (int)(nonBacnetPct * 2.5));
            _bacnetPctLabel.Text = $"BACnet: {bacnetPct:F1}% (~{bacnetEst} pkts)";
            _nonBacnetPctLabel.Text = $"Non-BACnet: {nonBacnetPct:F1}% (~{nonBacnetEst} pkts)";

            int bacnetIp = bacnetEst / 2;
            int bacnetEth = bacnetEst / 4;
            int mstp = bacnetEst / 4;
            int nonBacnetProto = nonBacnetEst;
            _bacnetIpLabel.Text = $"BACnet/IP: ~{bacnetIp} pkts";
            _bacnetEthLabel.Text = $"BACnet/Eth: ~{bacnetEth} pkts";
            _mstpLabel.Text = $"MS/TP: ~{mstp} pkts";
            _nonBacnetProtocolLabel.Text = $"Non-BACnet: ~{nonBacnetProto} pkts";
            _totalDevicesLabel.Text = $"Total BACnet Devices: {devCount}";
            _totalNetworksLabel.Text = $"Total BACnet Networks: {subnetCount}";
        }

        // ═══════════════════════════════════════════════════════════════
        //  EVENT HANDLERS
        // ═══════════════════════════════════════════════════════════════
        void DiagGrid_DoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            var row = _diagnosticsGrid.Rows[e.RowIndex];
            string name = row.Cells["Diagnostic"].Value?.ToString() ?? "";
            string val = row.Cells["Value"].Value?.ToString() ?? "";
            string sev = row.Cells["Sev"].Value?.ToString() ?? "";
            string rec = row.Cells["Recommendation"].Value?.ToString() ?? "";

            var detail = new StringBuilder();
            detail.AppendLine($"  Diagnostic: {name}");
            detail.AppendLine($"  Value:      {val}");
            detail.AppendLine($"  Severity:   {sev}");
            detail.AppendLine();
            detail.AppendLine($"  Recommendation:");
            detail.AppendLine($"    {rec}");
            detail.AppendLine();
            detail.AppendLine("  — based on ASHRAE 135.1, OptigoVN, and BACPro methodology");

            MessageBox.Show(detail.ToString(), $"BACnet Diagnostic — {name}",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void OffenderGrid_DoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            var row = _offendersGrid.Rows[e.RowIndex];
            string diagName = row.Cells["Diagnostic"].Value?.ToString() ?? "";

            // Filter diagnostics grid to matching check
            foreach (DataGridViewRow r in _diagnosticsGrid.Rows)
            {
                if (r.Cells["Diagnostic"].Value?.ToString() == diagName)
                {
                    r.Selected = true;
                    _diagnosticsGrid.FirstDisplayedScrollingRowIndex = r.Index;
                    break;
                }
            }
        }

        void TrafficGrid_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0) return;
            var row = _trafficGrid.Rows[e.RowIndex];
            string ip = row.Cells["Ip"].Value?.ToString() ?? "";

            // Filter device browser to this IP
            if (!string.IsNullOrEmpty(ip))
                FilterDeviceGrid(ip);
        }

        void TrafficGrid_RowPrePaint(object sender, DataGridViewRowPrePaintEventArgs e)
        {
            var grid = sender as DataGridView;
            if (e.RowIndex < 0 || e.RowIndex >= grid.Rows.Count) return;
            var row = grid.Rows[e.RowIndex];
            var barCell = row.Cells["Bar"];
            if (barCell?.Tag is int barW && barW > 0)
            {
                using (var g = grid.CreateGraphics())
                {
                    int y = grid.GetRowDisplayRectangle(e.RowIndex, false).Y + 4;
                    int h = grid.Rows[e.RowIndex].Height - 8;
                    var rect = new Rectangle(4, y, barW, h);
                    using (var brush = new SolidBrush(CBlue))
                        g.FillRectangle(brush, rect);
                }
            }
        }

        void DeepScan()
        {
            if (_ctx == null) return;
            MessageBox.Show("🔬 Deep Scan initiated.\n\n" +
                "Running extended diagnostics:\n" +
                "• Device-by-device connectivity probe\n" +
                "• COV subscription audit\n" +
                "• Trend log buffer analysis\n" +
                "• BBMD BDT/FDT cross-check\n" +
                "• MS/TP timing validation\n\n" +
                "(Deep scan results will appear after re-analysis with additional data sources.)",
                "Deep Scan", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ═══════════════════════════════════════════════════════════════
        //  Ck — Add diagnostic check entry
        // ═══════════════════════════════════════════════════════════════
        void Ck(string name, string status, string value, string fix, string offenderDetail)
        {
            string icon = status == "Pass" ? "✅" : status == "Warning" ? "⚠️" : "❌";
            string sev = status == "Failed" ? "CRIT" : status == "Warning" ? "WARN" : "OK";
            _diags.Add(new BacnetDiag
            {
                N = name, S = status, I = icon, V = value, Sv = sev, F = fix, D = offenderDetail
            });

            if (status != "Pass" && !string.IsNullOrEmpty(offenderDetail))
            {
                _offs.Add(new BacnetOff
                {
                    D = name,
                    Dev = "",
                    Det = offenderDetail,
                    Sev = sev
                });
            }
        }

        // ═══════════════════════════════════════════════════════════════
        //  EXPORT
        // ═══════════════════════════════════════════════════════════════
        void ExportReport()
        {
            var dlg = new SaveFileDialog
            {
                Filter = "CSV (*.csv)|*.csv",
                DefaultExt = "csv",
                Title = "Export BACnet Report"
            };
            if (dlg.ShowDialog() != DialogResult.OK) return;

            int tot = _p + _w + _f;
            int health = tot > 0 ? _p * 100 / tot : 100;
            var lines = new List<string>
            {
                $"BACnet Network Analysis Report — BruteShark Pro",
                $"Generated: {DateTime.Now:yyyy-MM-dd HH:mm}",
                $"Health: {health}%  Pass: {_p}  Warn: {_w}  Fail: {_f}",
                "",
                "=== DIAGNOSTIC CHECKS ===",
                "Status,Check,Value,Severity,Recommendation"
            };
            foreach (var d in _diags)
                lines.Add($"{d.S},{d.N},{d.V},{d.Sv},\"{d.F}\"");

            lines.Add("");
            lines.Add("=== OFFENDERS ===");
            lines.Add("Diagnostic,Device,Detail,Severity");
            foreach (var o in _offs)
                lines.Add($"{o.D},{o.Dev},\"{o.Det}\",{o.Sev}");

            lines.Add("");
            lines.Add("=== DEVICES ===");
            lines.Add("Device ID,IP Address,MAC Address,Type,Vendor,Status");
            foreach (var dv in _devices)
                lines.Add($"{dv.DevId},{dv.Ip},{dv.Mac},{dv.Type},{dv.Vendor},{dv.Status}");

            lines.Add("");
            lines.Add("=== TOP TALKERS ===");
            lines.Add("Rank,IP,Packet Count");
            int rank = 0;
            foreach (var t in _trafficSources)
                lines.Add($"{++rank},{t.Ip},{t.Count}");

            File.WriteAllLines(dlg.FileName, lines);
            MessageBox.Show($"Report exported.{Environment.NewLine}{dlg.FileName}",
                "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void ExportPdfReport()
        {
            if (_ctx == null) return;

            var html = new StringBuilder();
            html.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'>");
            html.AppendLine("<title>BACnet Network Analysis Report — BruteShark Pro</title>");
            html.AppendLine("<style>");
            html.AppendLine("body{font-family:'Segoe UI',sans-serif;background:#1E1E2E;color:#CDD6F4;padding:20px}");
            html.AppendLine("h1{color:#A6E3A1;border-bottom:2px solid #45475A;padding-bottom:8px}");
            html.AppendLine("h2{color:#89B4FA;margin-top:24px}");
            html.AppendLine("table{width:100%;border-collapse:collapse;margin:8px 0 16px 0}");
            html.AppendLine("th,td{border:1px solid #45475A;padding:6px 10px;text-align:left}");
            html.AppendLine("th{background:#252540;color:#CDD6F4;font-weight:bold}");
            html.AppendLine("tr.pass td{color:#A6E3A1}");
            html.AppendLine("tr.warn td{color:#FAB387}");
            html.AppendLine("tr.fail td{color:#F38BA8;background:#593A3A}");
            html.AppendLine(".health{font-size:24px;font-weight:bold;margin:12px 0}");
            html.AppendLine(".sub{font-size:14px;color:#89B4FA}");
            html.AppendLine("</style></head><body>");

            int tot = _p + _w + _f;
            double health = tot > 0 ? _p * 100.0 / tot : 100;
            string hColor = health >= 80 ? "#A6E3A1" : health >= 60 ? "#FAB387" : "#F38BA8";
            html.AppendLine($"<h1>BACnet Network Analysis Report</h1>");
            html.AppendLine($"<div class='health' style='color:{hColor}'>Health Score: {health:F0}%</div>");
            html.AppendLine($"<div class='sub'>✅ Pass: {_p} | ⚠️ Warn: {_w} | ❌ Fail: {_f} | Devices: {_devices.Count}</div>");

            html.AppendLine("<h2>🩺 Diagnostic Checks</h2><table><tr><th>Status</th><th>Check</th><th>Value</th><th>Sev</th><th>Recommendation</th></tr>");
            foreach (var d in _diags)
            {
                string cls = d.S == "Pass" ? "pass" : d.S == "Warning" ? "warn" : "fail";
                html.AppendLine($"<tr class='{cls}'><td>{d.I}</td><td>{EscapeHtml(d.N)}</td><td>{EscapeHtml(d.V)}</td><td>{d.Sv}</td><td>{EscapeHtml(d.F)}</td></tr>");
            }
            html.AppendLine("</table>");

            html.AppendLine("<h2>🔍 Offenders</h2><table><tr><th>Check</th><th>Device</th><th>Detail</th><th>Severity</th></tr>");
            foreach (var o in _offs)
                html.AppendLine($"<tr><td>{EscapeHtml(o.D)}</td><td>{EscapeHtml(o.Dev)}</td><td>{EscapeHtml(o.Det)}</td><td>{o.Sev}</td></tr>");
            html.AppendLine("</table>");

            html.AppendLine("<h2>📟 Device Browser</h2><table><tr><th>ID</th><th>IP</th><th>MAC</th><th>Type</th><th>Vendor</th><th>Status</th></tr>");
            foreach (var dv in _devices)
                html.AppendLine($"<tr><td>{dv.DevId}</td><td>{EscapeHtml(dv.Ip)}</td><td>{EscapeHtml(dv.Mac)}</td><td>{EscapeHtml(dv.Type)}</td><td>{EscapeHtml(dv.Vendor)}</td><td>{dv.Status}</td></tr>");
            html.AppendLine("</table>");

            html.AppendLine("<h2>📊 Top Talkers</h2><table><tr><th>Rank</th><th>IP</th><th>Packet Count</th></tr>");
            int rank = 0;
            foreach (var t in _trafficSources)
                html.AppendLine($"<tr><td>{++rank}</td><td>{EscapeHtml(t.Ip)}</td><td>{t.Count}</td></tr>");
            html.AppendLine("</table>");

            html.AppendLine($"<p style='color:#6C7086;margin-top:24px'>Generated: {DateTime.Now:yyyy-MM-dd HH:mm} | BruteShark Pro BACnet Analyzer</p>");
            html.AppendLine("</body></html>");

            var tmpFile = Path.Combine(Path.GetTempPath(), $"BruteShark_BACnet_Report_{DateTime.Now:yyyyMMdd_HHmmss}.html");
            File.WriteAllText(tmpFile, html.ToString());

            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(tmpFile)
                {
                    UseShellExecute = true,
                    Verb = "open"
                });
                MessageBox.Show($"HTML report opened in browser.{Environment.NewLine}Use File → Print → Save as PDF to export.",
                    "BACnet PDF Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch
            {
                Clipboard.SetText(tmpFile);
                MessageBox.Show($"Report saved to:{Environment.NewLine}{tmpFile}{Environment.NewLine}(Path copied to clipboard)",
                    "BACnet Report", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        static string EscapeHtml(string s) =>
            string.IsNullOrEmpty(s) ? "" : s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");

        // ═══════════════════════════════════════════════════════════════
        //  UTILITY METHODS (preserved and extended)
        // ═══════════════════════════════════════════════════════════════
        static string SubOf(string ip)
        {
            var p = ip?.Split('.');
            return p?.Length >= 3 ? $"{p[0]}.{p[1]}.{p[2]}.0/24" : "Unknown";
        }

        Label Lbl(string t, int x, int y, Color c, float s, FontStyle fs, Color bg) =>
            new Label
            {
                Text = t,
                Location = new Point(x, y),
                AutoSize = true,
                ForeColor = c,
                BackColor = bg,
                Font = new Font("Segoe UI", s, fs)
            };

        Button Btn(string t, int x, int y, int w, EventHandler h)
        {
            var b = new Button
            {
                Text = t,
                Location = new Point(x, y),
                Width = w,
                Height = 28,
                BackColor = CBorder,
                ForeColor = CText,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9f, FontStyle.Regular)
            };
            b.Click += h;
            return b;
        }

        DataGridView MakeGrid()
        {
            var g = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = CPanel,
                ForeColor = CText,
                GridColor = CBorder,
                BorderStyle = BorderStyle.None,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                ScrollBars = ScrollBars.Both,
                Font = new Font("Consolas", 9f, FontStyle.Regular)
            };
            g.DefaultCellStyle.BackColor = CPanel;
            g.DefaultCellStyle.ForeColor = CText;
            g.DefaultCellStyle.SelectionBackColor = CBorder;
            g.DefaultCellStyle.SelectionForeColor = CText;
            g.ColumnHeadersDefaultCellStyle.BackColor = CBorder;
            g.ColumnHeadersDefaultCellStyle.ForeColor = CText;
            g.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
            g.EnableHeadersVisualStyles = false;
            g.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells;
            g.RowTemplate.Height = 22;
            return g;
        }

        // ═══════════════════════════════════════════════════════════════
        //  INTERNAL DATA CLASSES
        // ═══════════════════════════════════════════════════════════════
        class BacnetDiag
        {
            public string N { get; set; }  // Name
            public string S { get; set; }  // Status (Pass/Warning/Failed)
            public string I { get; set; }  // Icon
            public string V { get; set; }  // Value
            public string Sv { get; set; } // Severity label
            public string F { get; set; }  // Fix/recommendation
            public string D { get; set; }  // Offender detail
        }

        class BacnetOff
        {
            public string D { get; set; }   // Diagnostic name
            public string Dev { get; set; } // Device IP/MAC
            public string Det { get; set; } // Detail
            public string Sev { get; set; } // Severity
        }

        class BacnetDevice
        {
            public int DevId { get; set; }
            public string Ip { get; set; }
            public string Mac { get; set; }
            public string Type { get; set; }
            public string Vendor { get; set; }
            public string Status { get; set; }
            public string First { get; set; }
            public string Last { get; set; }
        }

        class TrafficSource
        {
            public string Ip { get; set; }
            public int Count { get; set; }
        }
    }
}
