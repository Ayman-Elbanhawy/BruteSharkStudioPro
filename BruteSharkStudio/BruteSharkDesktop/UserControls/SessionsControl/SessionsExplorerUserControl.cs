using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    public partial class SessionsExplorerUserControl : UserControl
    {
        private SessionViewerUserControl _sessionViewerUserControl;
        private CommonUi.NetworkContext _networkContext;

        public int SessionsCount => this.sessionsDataGridView.RowCount;

        public SessionsExplorerUserControl(CommonUi.NetworkContext networkContext)
        {
            InitializeComponent();

            // Initialize the sessions gridview.
            _networkContext = networkContext;
            this.sessionsDataGridView.SelectionChanged += OnSessionsDataGridViewSelectionChanged;
            this.sessionsDataGridView.AllowUserToAddRows = false;

            // Add the Session Viewer control.
            _sessionViewerUserControl = new SessionViewerUserControl();
            _sessionViewerUserControl.Dock = DockStyle.Fill;
            this.bottomSplitContainer.Panel1.Controls.Add(_sessionViewerUserControl);

            // Initialize the filter columns Combo Box.
            InitializeColumnsNames();

            // Apply dark professional theme
            ApplyDarkTheme();
        }

        private void ApplyDarkTheme()
        {
            var bg = Color.FromArgb(0x1E, 0x1E, 0x2E);
            var panel = Color.FromArgb(0x25, 0x25, 0x40);
            var text = Color.FromArgb(0xCD, 0xD6, 0xF4);
            var border = Color.FromArgb(0x45, 0x47, 0x5A);
            var accent = Color.FromArgb(0x89, 0xB4, 0xFA);

            this.BackColor = bg;

            // Split containers
            this.mainSplitContainer.BackColor = border;
            this.mainSplitContainer.Panel1.BackColor = bg;
            this.mainSplitContainer.Panel2.BackColor = bg;
            this.bottomSplitContainer.BackColor = border;

            // DataGridView
            sessionsDataGridView.BackgroundColor = panel;
            sessionsDataGridView.ForeColor = text;
            sessionsDataGridView.GridColor = border;
            sessionsDataGridView.BorderStyle = BorderStyle.None;
            sessionsDataGridView.DefaultCellStyle.BackColor = panel;
            sessionsDataGridView.DefaultCellStyle.ForeColor = text;
            sessionsDataGridView.DefaultCellStyle.SelectionBackColor = border;
            sessionsDataGridView.DefaultCellStyle.SelectionForeColor = text;
            sessionsDataGridView.ColumnHeadersDefaultCellStyle.BackColor = border;
            sessionsDataGridView.ColumnHeadersDefaultCellStyle.ForeColor = text;
            sessionsDataGridView.EnableHeadersVisualStyles = false;
            sessionsDataGridView.RowHeadersVisible = false;
            sessionsDataGridView.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCellsExceptHeader;
            sessionsDataGridView.ScrollBars = ScrollBars.Both;

            // Filter group box
            filterSessionsGroupBox.ForeColor = text;
            filterSessionsGroupBox.BackColor = bg;

            // Filter controls
            filterTextBox.BackColor = panel;
            filterTextBox.ForeColor = text;
            filterTextBox.BorderStyle = BorderStyle.FixedSingle;
            columnsComboBox.BackColor = panel;
            columnsComboBox.ForeColor = text;

            // Buttons
            foreach (var btn in new[] { filterButton, clearFilterButton })
            {
                btn.BackColor = border;
                btn.ForeColor = text;
                btn.FlatStyle = FlatStyle.Flat;
                btn.FlatAppearance.BorderColor = accent;
            }
        }

        private void InitializeColumnsNames()
        {
            // TODO: use reflection to get only the properties with a Browsable attribute, than 
            // extract their DisplayName attribute value.
            string[] columns = {"Protocol", "Source Ip", "Source Port", "Destination Ip", "Destination Port"};

            foreach (var column in columns)
            {
                this.columnsComboBox.Items.Add(column);
                this.sessionsDataGridView.Columns.Add(columnName: column, headerText: column);
            }
        }

        private void OnSessionsDataGridViewSelectionChanged(object sender, EventArgs e)
        {
            var selectedRow = this.sessionsDataGridView.SelectedRows.Count > 0 ?
                              this.sessionsDataGridView.SelectedRows[0] : null;

            if (selectedRow is null)
                return;

            var session = _networkContext.NetworkSessions.Where(s =>
                                s.Protocol == Convert.ToString(selectedRow.Cells["Protocol"].Value) &
                                s.SourceIp == Convert.ToString(selectedRow.Cells["Source Ip"].Value) &
                                s.SourcePort.ToString() == Convert.ToString(selectedRow.Cells["Source Port"].Value) &
                                s.DestinationIp == Convert.ToString(selectedRow.Cells["Destination Ip"].Value) &
                                s.DestinationPort.ToString() == Convert.ToString(selectedRow.Cells["Destination Port"].Value))
                          .FirstOrDefault();

            if (session == null)
                return;

            // TODO: refactor session viewer to work with pcap processor network object
            // (after refactoring Tcp and Udp sessions to work with internet layer base class)
            if (session is PcapProcessor.TcpSession)
            {
                _sessionViewerUserControl.SetSessionView(
                    Casting.CastProcessorTcpSessionToBruteSharkDesktopTcpSession(
                        session as PcapProcessor.TcpSession));
            }
            else if (session is PcapProcessor.UdpSession)
            {
                _sessionViewerUserControl.SetSessionView(
                    Casting.CastProcessorUdpSessionToBruteSharkDesktopUdpSession(
                        session as PcapProcessor.UdpSession));
            }

        }

        public void AddSession(PcapProcessor.TcpSession tcpSession)
        {
            _networkContext.NetworkSessions.Add(tcpSession);
            this.SuspendLayout();

            this.sessionsDataGridView.Rows.Add(
                "TCP", 
                tcpSession.SourceIp, 
                tcpSession.SourcePort.ToString(), 
                tcpSession.DestinationIp, 
                tcpSession.DestinationPort.ToString());

            this.ResumeLayout();
        }

        public void AddSession(PcapProcessor.UdpSession udpSession)
        {
            _networkContext.NetworkSessions.Add(udpSession);
            this.SuspendLayout();

            this.sessionsDataGridView.Rows.Add(
                "UDP",
                udpSession.SourceIp,
                udpSession.SourcePort.ToString(),
                udpSession.DestinationIp,
                udpSession.DestinationPort.ToString());

            this.ResumeLayout();
        }

        private void filterButton_Click(object sender, EventArgs e)
        {
            try
            {
                var columnName = this.columnsComboBox.SelectedItem.ToString();
                var wantedValue = this.filterTextBox.Text;

                // Get all the rows that do not match the user's filter.
                DataGridViewRow[] rows = this.sessionsDataGridView.Rows
                    .Cast<DataGridViewRow>()
                    .Where(r => !(r.Cells[columnName].Value != null && r.Cells[columnName].Value.ToString().Equals(wantedValue)))
                    .ToArray();

                foreach (var row in rows)
                {
                    row.Visible = false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to filter the sessions. Message {ex.Message}");
            }
        }

        private void clearFilterButton_Click(object sender, EventArgs e)
        {
            foreach (DataGridViewRow row in this.sessionsDataGridView.Rows)
            {
                row.Visible = true;
            }
        }
    }
}
