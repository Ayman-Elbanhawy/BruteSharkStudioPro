using BruteSharkDesktop;
using PcapProcessor;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace BruteSharkDesktop
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // MainForm composes the processor, analyzer, sniffer, and the WinForms user
    // controls so the desktop workflow stays in one event-driven shell.
    public partial class MainForm : Form
    {
        private CancellationTokenSource _cts;
        private HashSet<string> _files;
        private CommonUi.NetworkContext _networkContext;
        private PcapProcessor.Processor _processor;
        private PcapProcessor.Sniffer _sniffer;
        private PcapAnalyzer.Analyzer _analyzer;

        private GenericTableUserControl _passwordsUserControl;
        private HashesUserControl _hashesUserControl;
        private NetworkMapUserControl _networkMapUserControl;
        private SessionsExplorerUserControl _sessionsExplorerUserControl;
        private FilesUserControl _filesUserControl;
        private DnsResponseUserControl _dnsResponseUserControl;
        private VoipCallsUserControl _voipCallsUserControl;

        // Phase 4+ module user controls
        private GenericTableUserControl _alertsUserControl;
        private GenericTableUserControl _beaconsUserControl;
        private GenericTableUserControl _ja3UserControl;
        private GenericTableUserControl _tlsCertsUserControl;
        private GenericTableUserControl _sshUserControl;
        private GenericTableUserControl _httpUserControl;
        private GenericTableUserControl _smbUserControl;
        private GenericTableUserControl _dhcpUserControl;
        private GenericTableUserControl _arpUserControl;
        private GenericTableUserControl _anomaliesUserControl;

        // Phase 3: Detection & intelligence engine
        private PcapAnalyzer.DetectionRuleEngine _detectionEngine;
        private PcapAnalyzer.BeaconDetectionModule _beaconModule;


        public MainForm()
        {
            InitializeComponent();

            _files = new HashSet<string>();
            _cts = new CancellationTokenSource();
            _networkContext = new CommonUi.NetworkContext();

            // Create the DAL and BLL objects.
            _processor = new PcapProcessor.Processor();
            _sniffer = new PcapProcessor.Sniffer();
            _analyzer = new PcapAnalyzer.Analyzer();
            _processor.BuildTcpSessions = true;
            _processor.BuildUdpSessions = true;

            // Wire packet, session, and parsing events once here so every capture
            // source (offline files and live capture) updates the same UI flow.
            _sniffer.UdpPacketArived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _sniffer.TcpPacketArived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));
            _sniffer.TcpSessionArrived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorTcpSessionToAnalyzerTcpSession(e.TcpSession));
            _sniffer.UdpSessionArrived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorUdpStreamToAnalyzerUdpStream(e.UdpSession));
            _sniffer.TcpSessionArrived += (s, e) => SwitchToMainThreadContext(() => OnSessionArived(e.TcpSession));
            _sniffer.UdpSessionArrived += (s, e) => SwitchToMainThreadContext(() => OnSessionArived(e.UdpSession));
            _processor.UdpPacketArived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _processor.TcpPacketArived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));
            _processor.TcpSessionArrived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorTcpSessionToAnalyzerTcpSession(e.TcpSession));
            _processor.UdpSessionArrived += (s, e) => _analyzer.Analyze(CommonUi.Casting.CastProcessorUdpStreamToAnalyzerUdpStream(e.UdpSession));
            _processor.TcpSessionArrived += (s, e) => SwitchToMainThreadContext(() => OnSessionArived(e.TcpSession));
            _processor.UdpSessionArrived += (s, e) => SwitchToMainThreadContext(() => OnSessionArived(e.UdpSession));
            _processor.FileProcessingStatusChanged += (s, e) => SwitchToMainThreadContext(() => OnFileProcessingStatusChanged(s, e));
            _processor.ProcessingPrecentsChanged += (s, e) => SwitchToMainThreadContext(() => OnProcessingPrecentsChanged(s, e));
            _processor.ProcessingFinished += (s, e) => SwitchToMainThreadContext(() => OnProcessingFinished(s, e));
            _analyzer.ParsedItemDetected += (s, e) => SwitchToMainThreadContext(() => OnParsedItemDetected(s, e));
            _analyzer.UpdatedItemProprertyDetected += (s, e) => SwitchToMainThreadContext(() => OnUpdatedItemProprertyDetected(s, e));

            // Phase 3: Initialize detection engine and beacon module
            _detectionEngine = new PcapAnalyzer.DetectionRuleEngine();
            _detectionEngine.RuleMatched += (s, e) => SwitchToMainThreadContext(() => OnRuleMatched(s, e));
            _beaconModule = new PcapAnalyzer.BeaconDetectionModule();
            _beaconModule.ParsedItemDetected += (s, e) => SwitchToMainThreadContext(() => OnBeaconDetected(s, e));

            // Wire detection engine into the packet pipeline
            _processor.UdpPacketArived += (s, e) => _detectionEngine.EvaluatePacket(
                CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _processor.TcpPacketArived += (s, e) => _detectionEngine.EvaluatePacket(
                CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));
            _processor.UdpPacketArived += (s, e) => _beaconModule.Analyze(
                CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _processor.TcpPacketArived += (s, e) => _beaconModule.Analyze(
                CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));

            InitilizeModulesUserControls();
            InitilizeFilesIconsList();
            InitilizeModulesCheckedListBox();
            InitilizeInterfacesComboBox();
            AddModuleTreeNodes();
            this.modulesTreeView.ExpandAll();
            ApplyProfessionalTheme();
            InitializeToolTips();
            CheckForUpdates();
        }

        private void InitilizeModulesUserControls()
        {
            // Recreate all views against the current network context. This is
            // also used when clearing results so the UI returns to a clean state.
            _networkMapUserControl = new NetworkMapUserControl(_networkContext);
            _networkMapUserControl.Dock = DockStyle.Fill;
            _sessionsExplorerUserControl = new SessionsExplorerUserControl(_networkContext);
            _sessionsExplorerUserControl.Dock = DockStyle.Fill;
            _hashesUserControl = new HashesUserControl(_networkContext);
            _hashesUserControl.Dock = DockStyle.Fill;
            _passwordsUserControl = new GenericTableUserControl();
            _passwordsUserControl.Dock = DockStyle.Fill;
            _filesUserControl = new FilesUserControl();
            _filesUserControl.Dock = DockStyle.Fill;
            _dnsResponseUserControl = new DnsResponseUserControl();
            _dnsResponseUserControl.Dock = DockStyle.Fill;
            _voipCallsUserControl = new VoipCallsUserControl();
            _voipCallsUserControl.Dock = DockStyle.Fill;

            // Phase 4+ module user controls
            _alertsUserControl = new GenericTableUserControl();
            _alertsUserControl.Dock = DockStyle.Fill;
            _beaconsUserControl = new GenericTableUserControl();
            _beaconsUserControl.Dock = DockStyle.Fill;
            _ja3UserControl = new GenericTableUserControl();
            _ja3UserControl.Dock = DockStyle.Fill;
            _tlsCertsUserControl = new GenericTableUserControl();
            _tlsCertsUserControl.Dock = DockStyle.Fill;
            _sshUserControl = new GenericTableUserControl();
            _sshUserControl.Dock = DockStyle.Fill;
            _httpUserControl = new GenericTableUserControl();
            _httpUserControl.Dock = DockStyle.Fill;
            _smbUserControl = new GenericTableUserControl();
            _smbUserControl.Dock = DockStyle.Fill;
            _dhcpUserControl = new GenericTableUserControl();
            _dhcpUserControl.Dock = DockStyle.Fill;
            _arpUserControl = new GenericTableUserControl();
            _arpUserControl.Dock = DockStyle.Fill;
            _anomaliesUserControl = new GenericTableUserControl();
            _anomaliesUserControl.Dock = DockStyle.Fill;
        }

        private void InitilizeInterfacesComboBox()
        {
            foreach (string interfaceName in _sniffer.AvailiableDevicesNames)
            {
                this.interfacesComboBox.Items.Add(interfaceName);
            }
        }

        private void InitilizeModulesCheckedListBox()
        {
            foreach (var module_name in _analyzer.AvailableModulesNames)
            {
                this.modulesCheckedListBox.Items.Add(module_name, isChecked: false);
            }
        }

        private void OnProcessingFinished(object sender, EventArgs e)
        {
            this.progressBar.Value = this.progressBar.Maximum;
            this.ResumeLayout();
            HandleFailedFiles();

            // Phase 3: Run beacon detection on accumulated connections
            _beaconModule.DetectBeacons();

            // Phase 3: Update UI with alert counts from detection engine
            var alertCount = _detectionEngine.Matches.Count + _networkContext.BeaconCount;
            if (alertCount > 0)
            {
                if (this.modulesTreeView.Nodes["DetectionNode"] != null &&
                    this.modulesTreeView.Nodes["DetectionNode"].Nodes["AlertsNode"] != null)
                {
                    this.modulesTreeView.Nodes["DetectionNode"].Nodes["AlertsNode"].Text =
                        $"Alerts ({alertCount})";
                }
            }
        }

        private void HandleFailedFiles()
        {
            // The tag holds the full file path.
            var failedFilesString = string.Join(
                Environment.NewLine,
                filesListView.Items
                    .Cast<ListViewItem>()
                    .Where(x => x.SubItems[2].Text == "Failed")
                    .Select(x => x.Tag.ToString() + Environment.NewLine)
                    .ToList());

            if (failedFilesString.Length > 0)
            {
                var failedFilesMessage =
@$"BruteShark Desktop Studio failed to analyze to following files:
{Environment.NewLine}{failedFilesString}
 Note: if your files are in PCAPNG format it possible to convert them to a PCAP format using Tshark: 
tshark -F pcap -r <pcapng file> -w <pcap file>";

                MessageBox.Show(failedFilesMessage);
            }
        }

        private void OnSessionArived(PcapProcessor.TcpSession session)
        {
            _sessionsExplorerUserControl.AddSession(session);
            this.modulesTreeView.Nodes["NetworkNode"].Nodes["SessionsNode"].Text = $"Sessions ({_sessionsExplorerUserControl.SessionsCount})";
        }

        private void OnSessionArived(PcapProcessor.UdpSession session)
        {
            _sessionsExplorerUserControl.AddSession(session);
            this.modulesTreeView.Nodes["NetworkNode"].Nodes["SessionsNode"].Text = $"Sessions ({_sessionsExplorerUserControl.SessionsCount})";
        }

        private void SwitchToMainThreadContext(Action func)
        {
            // Thread-Safe mechanism:
            // Check if we are currently running in a different thread than the one that 
            // control was created on, if so we invoke a call to our function again, but because 
            // we used the invoke method again from our form the caller this time will be the 
            // the thread that created the form.
            // For more details: 
            // https://docs.microsoft.com/en-us/dotnet/framework/winforms/controls/how-to-make-thread-safe-calls-to-windows-forms-controls
            if (InvokeRequired)
            {
                Invoke(func);
                return;
            }

            Invoke(func);
        }

        private void OnProcessingPrecentsChanged(object sender, PcapProcessor.ProcessingPrecentsChangedEventArgs e)
        {
            if (e.Precents <= 90)
            {
                this.progressBar.Value = e.Precents;
            }
        }

        private void OnFileProcessingStatusChanged(object sender, FileProcessingStatusChangedEventArgs e)
        {
            var currentFileListViewItem = this.filesListView.FindItemWithText(
                Path.GetFileName(e.FilePath),
                true,
                0,
                false);

            if (e.Status == FileProcessingStatus.Started)
            {
                currentFileListViewItem.ForeColor = Color.Red;
                currentFileListViewItem.SubItems[2].Text = "On Process..";
            }
            else if (e.Status == FileProcessingStatus.Finished)
            {
                currentFileListViewItem.ForeColor = Color.Blue;
                currentFileListViewItem.SubItems[2].Text = "Analyzed";
            }
            else if (e.Status == FileProcessingStatus.Faild)
            {
                currentFileListViewItem.ForeColor = Color.DarkOrange;
                currentFileListViewItem.SubItems[2].Text = "Failed";
            }
        }

        private void InitilizeFilesIconsList()
        {
            this.filesListView.SmallImageList = new ImageList();
            ImageList imgList = new ImageList();
            imgList.ImageSize = new Size(22, 22);
            imgList.Images.Add(Properties.Resources.Wireshark_Icon);
            this.filesListView.SmallImageList = imgList;
        }

        private void OnParsedItemDetected(object sender, PcapAnalyzer.ParsedItemDetectedEventArgs e)
        {
            if (e.ParsedItem is PcapAnalyzer.NetworkPassword)
            {
                var password = e.ParsedItem as PcapAnalyzer.NetworkPassword;
                _networkContext.AddPassword(password);
                _passwordsUserControl.AddDataToTable(password);
                this.modulesTreeView.Nodes["CredentialsNode"].Nodes["PasswordsNode"].Text = $"Passwords ({_passwordsUserControl.ItemsCount})";
                _networkMapUserControl.HandlePassword(password);
            }
            else if (e.ParsedItem is PcapAnalyzer.NetworkHash)
            {
                var hash = e.ParsedItem as PcapAnalyzer.NetworkHash;
                _hashesUserControl.AddHash(hash);
                this.modulesTreeView.Nodes["CredentialsNode"].Nodes["HashesNode"].Text = $"Hashes ({_hashesUserControl.HashesCount})";
                _networkMapUserControl.HandleHash(hash);
            }
            else if (e.ParsedItem is PcapAnalyzer.NetworkConnection)
            {
                var connection = e.ParsedItem as PcapAnalyzer.NetworkConnection;
                _networkContext.HandleNetworkConection(connection);
                _networkMapUserControl.AddEdge(connection.Source, connection.Destination);
                this.modulesTreeView.Nodes["NetworkNode"].Nodes["NetworkMapNode"].Text = $"Network Map ({_networkMapUserControl.NodesCount})";
            }
            else if (e.ParsedItem is PcapAnalyzer.NetworkFile)
            {
                var fileObject = e.ParsedItem as PcapAnalyzer.NetworkFile;
                _networkContext.AddNetworkFile(fileObject);
                _filesUserControl.AddFile(fileObject);
                this.modulesTreeView.Nodes["DataNode"].Nodes["FilesNode"].Text = $"Files ({_filesUserControl.FilesCount})";
            }
            else if (e.ParsedItem is PcapAnalyzer.DnsNameMapping)
            {
                var dnsResponse = e.ParsedItem as PcapAnalyzer.DnsNameMapping;
                _dnsResponseUserControl.AddNameMapping(dnsResponse);
                this.modulesTreeView.Nodes["NetworkNode"].Nodes["DnsResponsesNode"].Text = $"DNS Responses ({_dnsResponseUserControl.AnswerCount})";
                _networkMapUserControl.HandleDnsNameMapping(dnsResponse);
            }
            else if (e.ParsedItem is PcapAnalyzer.VoipCall)
            {
                var voipCall = CommonUi.Casting.CastAnalyzerVoipCallToPresentationVoipCall(e.ParsedItem as PcapAnalyzer.VoipCall);
                _networkContext.AddVoipCall(e.ParsedItem as PcapAnalyzer.VoipCall);
                _voipCallsUserControl.AddVoipCall(voipCall);
                this.modulesTreeView.Nodes["DataNode"].Nodes["VoipCallsNode"].Text = $"Voip Calls ({_voipCallsUserControl.VoipCallsCount})";
            }
            else if (e.ParsedItem is PcapAnalyzer.Ja3Fingerprint)
            {
                // JA3 fingerprint detected - log and track
                var ja3 = e.ParsedItem as PcapAnalyzer.Ja3Fingerprint;
                _networkContext.HandleJa3Fingerprint(ja3);
                _ja3UserControl.AddDataToTable(ja3);
                if (this.modulesTreeView.Nodes["FingerprintsNode"].Nodes["Ja3Node"] != null)
                    this.modulesTreeView.Nodes["FingerprintsNode"].Nodes["Ja3Node"].Text = $"JA3/JA3S ({_networkContext.Ja3Count})";
            }
            else if (e.ParsedItem is PcapAnalyzer.BeaconResult)
            {
                // Beacon detection result
                var beacon = e.ParsedItem as PcapAnalyzer.BeaconResult;
                _networkContext.AddBeaconResult(beacon);
                _beaconsUserControl.AddDataToTable(beacon);
                if (this.modulesTreeView.Nodes["DetectionNode"].Nodes["BeaconsNode"] != null)
                    this.modulesTreeView.Nodes["DetectionNode"].Nodes["BeaconsNode"].Text = $"C2 Beacons ({_networkContext.BeaconCount})";
            }
            else if (e.ParsedItem is PcapAnalyzer.PayloadAlert)
            {
                var alert = e.ParsedItem as PcapAnalyzer.PayloadAlert;
                _networkContext.AddPayloadAlert(alert);
                _alertsUserControl.AddDataToTable(alert);
                // Also add as detection match for rule-like alerts
                _networkContext.AddDetectionMatch(new PcapAnalyzer.RuleMatch
                {
                    RuleName = alert.AlertType,
                    Severity = alert.Severity,
                    SourceIp = alert.SourceIp,
                    DestinationIp = alert.DestinationIp,
                    MatchDetails = alert.Details
                });
                if (this.modulesTreeView.Nodes["DetectionNode"].Nodes["AlertsNode"] != null)
                    this.modulesTreeView.Nodes["DetectionNode"].Nodes["AlertsNode"].Text = $"Alerts ({_networkContext.PayloadAlerts.Count})";
            }
            else if (e.ParsedItem is PcapAnalyzer.DhcpLease)
            {
                var lease = e.ParsedItem as PcapAnalyzer.DhcpLease;
                _networkContext.AddDhcpLease(lease);
                _dhcpUserControl.AddDataToTable(lease);
                if (this.modulesTreeView.Nodes["ProtocolsNode"].Nodes["DhcpNode"] != null)
                    this.modulesTreeView.Nodes["ProtocolsNode"].Nodes["DhcpNode"].Text = $"DHCP ({_networkContext.DhcpLeases.Count})";
            }
            else if (e.ParsedItem is PcapAnalyzer.SshServerFingerprint)
            {
                var ssh = e.ParsedItem as PcapAnalyzer.SshServerFingerprint;
                _networkContext.AddSshFingerprint(ssh);
                _sshUserControl.AddDataToTable(ssh);
                if (this.modulesTreeView.Nodes["FingerprintsNode"].Nodes["SshNode"] != null)
                    this.modulesTreeView.Nodes["FingerprintsNode"].Nodes["SshNode"].Text = $"SSH ({_networkContext.SshFingerprints.Count})";
            }
            else if (e.ParsedItem is PcapAnalyzer.HttpTransaction)
            {
                var http = e.ParsedItem as PcapAnalyzer.HttpTransaction;
                _networkContext.AddHttpTransaction(http);
                _httpUserControl.AddDataToTable(http);
                if (this.modulesTreeView.Nodes["ProtocolsNode"].Nodes["HttpNode"] != null)
                    this.modulesTreeView.Nodes["ProtocolsNode"].Nodes["HttpNode"].Text = $"HTTP ({_networkContext.HttpTransactions.Count})";
            }
            else if (e.ParsedItem is PcapAnalyzer.TlsCertificate)
            {
                var cert = e.ParsedItem as PcapAnalyzer.TlsCertificate;
                _networkContext.AddTlsCertificate(cert);
                _tlsCertsUserControl.AddDataToTable(cert);
                if (this.modulesTreeView.Nodes["FingerprintsNode"].Nodes["TlsCertsNode"] != null)
                    this.modulesTreeView.Nodes["FingerprintsNode"].Nodes["TlsCertsNode"].Text = $"TLS Certs ({_networkContext.TlsCertificates.Count})";
            }
            else if (e.ParsedItem is PcapAnalyzer.PayloadAlert)
            {
                var alert = e.ParsedItem as PcapAnalyzer.PayloadAlert;
                _networkContext.AddPayloadAlert(alert);
                _alertsUserControl.AddDataToTable(alert);
                if (this.modulesTreeView.Nodes["DetectionNode"]?.Nodes["AlertsNode"] != null)
                    this.modulesTreeView.Nodes["DetectionNode"].Nodes["AlertsNode"].Text = $"Alerts ({_alertsUserControl.ItemsCount})";
                // Also track in anomalies if stats-related
                if (alert.AlertType?.Contains("Anomaly") == true || alert.AlertType?.Contains("Spike") == true || alert.AlertType?.Contains("Rate") == true)
                {
                    _anomaliesUserControl.AddDataToTable(alert);
                    if (this.modulesTreeView.Nodes["AnomaliesNode"] != null)
                        this.modulesTreeView.Nodes["AnomaliesNode"].Text = $"Anomalies ({_anomaliesUserControl.ItemsCount})";
                }
            }
        }

        private void OnUpdatedItemProprertyDetected(object sender, PcapAnalyzer.UpdatedPropertyInItemeventArgs e)
        {
            if (e.ParsedItem is PcapAnalyzer.VoipCall)
            {
                var voipCall = CommonUi.Casting.CastAnalyzerVoipCallToPresentationVoipCall(e.ParsedItem as PcapAnalyzer.VoipCall);
                _voipCallsUserControl.UpdateVoipCall(voipCall, e.PropertyChanged, e.NewPropertyValue);
            }
        }

        // Phase 3: Detection rule match handler
        private void OnRuleMatched(object sender, PcapAnalyzer.RuleMatchEventArgs e)
        {
            _networkContext.AddDetectionMatch(e.Match);
        }

        // Phase 3: Beacon detected handler
        private void OnBeaconDetected(object sender, PcapAnalyzer.ParsedItemDetectedEventArgs e)
        {
            if (e.ParsedItem is PcapAnalyzer.BeaconResult beacon)
            {
                _networkContext.AddBeaconResult(beacon);
            }
        }

        private void addFilesButton_Click(object sender, EventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            openFileDialog.Multiselect = true;

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                foreach (string filePath in openFileDialog.FileNames)
                {
                    AddFile(filePath);
                }
            }
        }

        private void AddFile(string filePath)
        {
            _files.Add(filePath);

            var listViewRow = new ListViewItem(
                new string[]
                {
                    Path.GetFileName(filePath),
                    new FileInfo(filePath).Length.ToString(),
                    "Wait"
                }
                , 0);

            listViewRow.Tag = new { FilePath = filePath, Status = "Wait" };
            this.filesListView.Items.Add(listViewRow);
        }

        private void RunButton_Click(object sender, EventArgs e)
        {
            // Reset all files status.
            foreach (ListViewItem item in this.filesListView.Items)
            {
                item.ForeColor = Color.Black;
                item.SubItems[2].Text = "Wait";
            }

            // Keep the WinForms UI responsive while large captures are processed.
            new Thread(() => _processor.ProcessPcaps(this._files)).Start();
        }

        private void ModulesTreeView_AfterSelect(object sender, TreeViewEventArgs e)
        {
            this.modulesSplitContainer.Panel2.Controls.Clear();

            switch (e.Node.Name)
            {
                case "PasswordsNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_passwordsUserControl);
                    break;
                case "HashesNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_hashesUserControl);
                    break;
                case "NetworkMapNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_networkMapUserControl);
                    break;
                case "SessionsNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_sessionsExplorerUserControl);
                    break;
                case "FilesNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_filesUserControl);
                    break;
                case "DnsResponsesNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_dnsResponseUserControl);
                    break;
                case "VoipCallsNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_voipCallsUserControl);
                    break;
                // Phase 4+ new module nodes
                case "AlertsNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_alertsUserControl);
                    break;
                case "BeaconsNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_beaconsUserControl);
                    break;
                case "Ja3Node":
                    this.modulesSplitContainer.Panel2.Controls.Add(_ja3UserControl);
                    break;
                case "TlsCertsNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_tlsCertsUserControl);
                    break;
                case "SshNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_sshUserControl);
                    break;
                case "HttpNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_httpUserControl);
                    break;
                case "SmbNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_smbUserControl);
                    break;
                case "DhcpNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_dhcpUserControl);
                    break;
                case "ArpNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_arpUserControl);
                    break;
                case "AnomaliesNode":
                    this.modulesSplitContainer.Panel2.Controls.Add(_anomaliesUserControl);
                    break;
                default:
                    break;
            }
        }

        private void RemoveFilesButton_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem item in filesListView.SelectedItems)
            {
                _files.Remove(item.Tag.ToString());
                item.Remove();
            }
        }

        private void ModulesCheckedListBox_ItemCheck(object sender, ItemCheckEventArgs e)
        {
            var module_name = ((CheckedListBox)sender).Items[e.Index].ToString();

            if (e.NewValue == CheckState.Checked)
            {
                _analyzer.AddModule(module_name);
            }
            else
            {
                _analyzer.RemoveModule(module_name);
            }
        }

        private void BuildTcpSessionsCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (buildTcpSessionsCheckBox.CheckState == CheckState.Checked)
            {
                buildTcpSessionsCheckBox.Text = "Build TCP Sessions: ON";
                _processor.BuildTcpSessions = true;
                _sniffer.BuildTcpSessions = true;
            }
            else if (buildTcpSessionsCheckBox.CheckState == CheckState.Unchecked)
            {
                buildTcpSessionsCheckBox.Text = "Build TCP Sessions: OFF";
                _processor.BuildTcpSessions = false;
                _sniffer.BuildTcpSessions = false;
                MessageOnBuildSessionsConfigurationChanged();
            }
        }

        private void BuildUdpSessionsCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            if (buildUdpSessionsCheckBox.CheckState == CheckState.Checked)
            {
                buildUdpSessionsCheckBox.Text = "Build UDP Sessions: ON";
                this._processor.BuildUdpSessions = true;
                this._sniffer.BuildUdpSessions = true;
            }
            else if (buildUdpSessionsCheckBox.CheckState == CheckState.Unchecked)
            {
                buildUdpSessionsCheckBox.Text = "Build UDP Sessions: OFF";
                this._processor.BuildUdpSessions = false;
                this._sniffer.BuildUdpSessions = false;
                MessageOnBuildSessionsConfigurationChanged();
            }
        }

        private void MessageOnBuildSessionsConfigurationChanged()
        {
            Utilities.ShowInfoMessageBox(@"NOTE, Disabling sessions reconstruction means that BruteShark will not analyze full sessions,
This means a faster processing but also that some obects may not be extracted.");
        }

        private void LiveCaptureButton_Click(object sender, EventArgs e)
        {
            if (this.interfacesComboBox.SelectedItem == null)
            {
                MessageBox.Show("No interface selected");
                return;
            }

            if (filterTextBox.Text != string.Empty && filterTextBox.Text != "<INSERT BPF FILTER HERE>")
            {
                if (Sniffer.CheckCaptureFilter(filterTextBox.Text))
                {
                    _sniffer.Filter = filterTextBox.Text;
                }
                else
                {
                    MessageBox.Show("Invalid BPF filter! please fix filter");
                    return;
                }
            }

            _sniffer.SelectedDeviceName = this.interfacesComboBox.SelectedItem.ToString();
            StartLiveCaptureAsync();
        }

        private async void StartLiveCaptureAsync()
        {
            this.progressBar.CustomText = "Live capture is ON...";
            this.progressBar.Refresh();
            _cts.Dispose();
            _cts = new CancellationTokenSource();
            var ct = _cts.Token;
            await Task.Run(() => _sniffer.StartSniffing(ct));

            // We wait here until the sniffing will be stoped (by the stop button).
            this.progressBar.CustomText = string.Empty;
            this.progressBar.Refresh();
            Utilities.ShowInfoMessageBox("Capture Stoped");
        }

        private void StopCaptureButton_Click(object sender, EventArgs e)
        {
            _cts.Cancel();
        }

        private void promiscuousCheckBox_CheckStateChanged(object sender, EventArgs e)
        {
            if (promiscuousCheckBox.CheckState == CheckState.Checked)
            {
                _sniffer.PromisciousMode = true;
            }
            else if (promiscuousCheckBox.CheckState == CheckState.Unchecked)
            {
                _sniffer.PromisciousMode = false;
            }
        }

        private void filterTextBox_TextChanged(object sender, EventArgs e)
        {
            if (Sniffer.CheckCaptureFilter(filterTextBox.Text))
            {
                filterTextBox.BackColor = Color.LightBlue;
            }
            else
            {
                filterTextBox.BackColor = Color.LightCoral;
            }
        }

        private void exportResutlsButton_Click(object sender, EventArgs e)
        {
            var selecetDirectoryDialog = new FolderBrowserDialog();

            if (selecetDirectoryDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    var outputDirectoryPath = selecetDirectoryDialog.SelectedPath;

                    // Export each result set using the same output structure that
                    // the CLI uses so screenshots, help text, and test data match.
                    this.progressBar.CustomText = $"Exporting results to output folder: {outputDirectoryPath}...";
                    this.progressBar.Refresh();
                    CommonUi.Exporting.ExportFiles(outputDirectoryPath, _filesUserControl.Files);
                    CommonUi.Exporting.ExportNetworkMap(outputDirectoryPath, _networkContext.Connections);
                    CommonUi.Exporting.ExportVoipCalls(outputDirectoryPath, _voipCallsUserControl.VoipCalls);
                    CommonUi.Exporting.ExportNetworkNodesData(outputDirectoryPath, _networkContext.GetAllNodes());
                    CommonUi.Exporting.ExportDnsMappings(outputDirectoryPath, _networkContext.DnsMappings);
                    CommonUi.Exporting.ExportJa3Fingerprints(outputDirectoryPath, _networkContext.Ja3Fingerprints);
                    CommonUi.Exporting.ExportBeaconResults(outputDirectoryPath, _networkContext.BeaconResults);
                    CommonUi.Exporting.ExportRuleMatches(outputDirectoryPath, _networkContext.DetectionMatches);
                    ExportHashes(outputDirectoryPath, _networkContext.Hashes);

                    // Export the full interactive HTML forensic report
                    var htmlReportPath = CommonUi.FullHtmlReportGenerator.ExportFullHtmlReport(
                        outputDirectoryPath, _networkContext, "BruteShark_Full_Report");
                    this.progressBar.CustomText = string.Empty;

                    Utilities.ShowInfoMessageBox($"Successfully exported results including Full HTML Report: {htmlReportPath}");
                }
                catch (Exception ex)
                {
                    Utilities.ShowInfoMessageBox($"Failed to export results: {ex.Message}");
                }
            }
        }

        private void ExportHashes(string outputDirectoryPath, HashSet<PcapAnalyzer.NetworkHash> hashes)
        {
            if (!hashes.Any())
            {
                return;
            }

            // Export each hash family separately so the generated files can be
            // used directly as Hashcat input without manual filtering.
            var hashesDirectoryPath = Path.Combine(outputDirectoryPath, "Hashes");
            Directory.CreateDirectory(hashesDirectoryPath);

            foreach (var hashType in hashes.Select(hash => hash.HashType).Distinct())
            {
                try
                {
                    var outputFilePath = CommonUi.Exporting.GetUniqueFilePath(Path.Combine(
                        hashesDirectoryPath,
                        $"Brute Shark - {hashType} Hashcat Export.txt"));

                    using (var streamWriter = new StreamWriter(outputFilePath, true))
                    {
                        foreach (var hash in hashes.Where(hash => hash.HashType == hashType))
                        {
                            streamWriter.WriteLine(BruteForce.Utilities.ConvertToHashcatFormat(
                                CommonUi.Casting.CastAnalyzerHashToBruteForceHash(hash)));
                        }
                    }
                }
                catch
                {
                    // Keep exporting other hash types when a specific type is unsupported by Hashcat.
                }
            }
        }

        private void clearResutlsButton_Click(object sender, EventArgs e)
        {
            _networkContext = new CommonUi.NetworkContext();
            _analyzer.Clear();

            // Clear all modules user controls by recreating them. 
            InitilizeModulesUserControls();

            // Remove the items count of each module from the tree view (e.g "DNS (13)" -> "DNS").
            foreach (var node in Utilities.IterateAllNodes(modulesTreeView.Nodes))
            {
                var index = node.Text.LastIndexOf('(');

                if (index > 0)
                {
                    node.Text = node.Text.Substring(0, index);
                }
            }

            // Select the head of the modules tree view to force refreshing of the current user control.
            modulesTreeView.SelectedNode = modulesTreeView.Nodes[0];
        }

        private async void CheckForUpdates()
        {
            try
            {
                var updaterResponse = await GithubAutoUpdater.ShouldUpdate(
                    ownerName: "Ayman-Elbanhawy",
                    projectName: "BruteSharkStudio");

                if (updaterResponse.ShouldUpdate)
                {
                    var userResponse = Utilities.ShowInfoMessageBox(
                        "New version of BruteShark Desktop Studio is available!", 
                        MessageBoxButtons.YesNo);

                    if (userResponse == DialogResult.Yes)
                    {
                        // Open the new version URL using the default browser.
                        Process browserProcess = new Process();
                        browserProcess.StartInfo.UseShellExecute = true;
                        browserProcess.StartInfo.FileName = updaterResponse.NewVersionUrl;
                        browserProcess.Start();
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// Add new module tree nodes for Detection, Fingerprints, Protocols, and Anomalies.
        /// Called after InitializeComponent so nodes are added after the existing designer nodes.
        /// </summary>
        private void AddModuleTreeNodes()
        {
            // Detection top-level node
            var detectionNode = new TreeNode
            {
                Name = "DetectionNode",
                Text = "Detection & Alerts"
            };
            detectionNode.Nodes.Add(new TreeNode { Name = "AlertsNode", Text = "Alerts" });
            detectionNode.Nodes.Add(new TreeNode { Name = "BeaconsNode", Text = "C2 Beacons" });

            // Fingerprints top-level node
            var fingerprintsNode = new TreeNode
            {
                Name = "FingerprintsNode",
                Text = "Fingerprints & TLS"
            };
            fingerprintsNode.Nodes.Add(new TreeNode { Name = "Ja3Node", Text = "JA3/JA3S" });
            fingerprintsNode.Nodes.Add(new TreeNode { Name = "TlsCertsNode", Text = "TLS Certificates" });
            fingerprintsNode.Nodes.Add(new TreeNode { Name = "SshNode", Text = "SSH" });

            // Protocols top-level node
            var protocolsNode = new TreeNode
            {
                Name = "ProtocolsNode",
                Text = "Protocol Analysis"
            };
            protocolsNode.Nodes.Add(new TreeNode { Name = "HttpNode", Text = "HTTP" });
            protocolsNode.Nodes.Add(new TreeNode { Name = "SmbNode", Text = "SMB" });
            protocolsNode.Nodes.Add(new TreeNode { Name = "DhcpNode", Text = "DHCP" });
            protocolsNode.Nodes.Add(new TreeNode { Name = "ArpNode", Text = "ARP" });

            // Anomalies top-level node
            var anomaliesNode = new TreeNode
            {
                Name = "AnomaliesNode",
                Text = "Anomalies"
            };
            anomaliesNode.Nodes.Add(new TreeNode { Name = "AnomaliesDummy", Text = "(awaiting data)" });

            // Add all new nodes to the tree view after the existing ones
            this.modulesTreeView.Nodes.Add(detectionNode);
            this.modulesTreeView.Nodes.Add(fingerprintsNode);
            this.modulesTreeView.Nodes.Add(protocolsNode);
            this.modulesTreeView.Nodes.Add(anomaliesNode);
        }

        /// <summary>
        /// Apply a dark professional theme to the entire UI.
        /// Sets dark backgrounds, light text, flat buttons, and consistent font.
        /// </summary>
        private void ApplyProfessionalTheme()
        {
            // Form background
            this.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);

            // Tree view styling
            this.modulesTreeView.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
            this.modulesTreeView.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
            this.modulesTreeView.Font = new Font("Segoe UI", 10f, FontStyle.Regular);
            this.modulesTreeView.LineColor = Color.FromArgb(0x45, 0x47, 0x5A);

            // Split containers
            this.mainSplitContainer.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.modulesSplitContainer.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.modulesSplitContainer.Panel1.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
            this.modulesSplitContainer.Panel2.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);
            this.secondaryLowerSplitContainer.BackColor = Color.FromArgb(0x1E, 0x1E, 0x2E);

            // Side panel width
            if (this.modulesSplitContainer.SplitterDistance < 250)
            {
                this.modulesSplitContainer.SplitterDistance = 250;
            }

            // Style all buttons
            foreach (Control ctrl in GetAllControls(this))
            {
                if (ctrl is Button btn)
                {
                    btn.FlatStyle = FlatStyle.Flat;
                    btn.FlatAppearance.BorderColor = Color.FromArgb(0x45, 0x47, 0x5A);
                    btn.BackColor = Color.FromArgb(0x45, 0x47, 0x5A);
                    btn.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                    btn.Font = new Font("Segoe UI", 11f, FontStyle.Regular);
                }
                else if (ctrl is GroupBox gb)
                {
                    gb.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                }
                else if (ctrl is CheckBox cb)
                {
                    cb.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                }
                else if (ctrl is ComboBox combo)
                {
                    combo.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
                    combo.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                }
                else if (ctrl is TextBox tb)
                {
                    tb.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
                    tb.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                }
                else if (ctrl is CheckedListBox clb)
                {
                    clb.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
                    clb.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                }
                else if (ctrl is ListView lv)
                {
                    lv.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
                    lv.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
                }
            }

            // Progress bar styling
            this.progressBar.BackColor = Color.FromArgb(0x25, 0x25, 0x40);
            this.progressBar.ForeColor = Color.FromArgb(0xCD, 0xD6, 0xF4);
        }

        /// <summary>
        /// Recursively collect all controls within a container.
        /// </summary>
        private static IEnumerable<Control> GetAllControls(Control container)
        {
            foreach (Control c in container.Controls)
            {
                yield return c;
                foreach (var child in GetAllControls(c))
                    yield return child;
            }
        }

        /// <summary>
        /// Create and assign ToolTip text to every interactive control on the form.
        /// Called after ApplyProfessionalTheme() so the ToolTip picks up the final layout.
        /// </summary>
        private void InitializeToolTips()
        {
            var toolTip = new ToolTip();
            toolTip.AutoPopDelay = 8000;
            toolTip.InitialDelay = 500;
            toolTip.ReshowDelay = 200;
            toolTip.ShowAlways = true;
            toolTip.IsBalloon = false;

            // ── File analysis buttons ──
            toolTip.SetToolTip(this.runButton, "Process all loaded PCAP files");
            toolTip.SetToolTip(this.addFilesButton, "Add PCAP/PCAPNG files for analysis");
            toolTip.SetToolTip(this.removeFilesButton, "Remove selected files from the list");
            toolTip.SetToolTip(this.filesListView, "List of PCAP/PCAPNG files loaded for analysis");

            // ── Action buttons ──
            toolTip.SetToolTip(this.exportResutlsButton, "Export all findings to HTML, JSON, CSV, and other formats");
            toolTip.SetToolTip(this.clearResutlsButton, "Clear all current results and reset the workspace");

            // ── Live capture ──
            toolTip.SetToolTip(this.liveCaptureButton, "Start live network packet capture on selected interface");
            toolTip.SetToolTip(this.stopCaptureButton, "Stop live capture immediately");
            toolTip.SetToolTip(this.interfacesComboBox, "Select network interface for live capture");
            toolTip.SetToolTip(this.promiscuousCheckBox, "Capture all packets on the network, not just those addressed to this PC");
            toolTip.SetToolTip(this.filterTextBox, "Berkeley Packet Filter expression (e.g., 'tcp port 80' or 'host 192.168.1.1')");

            // ── Options ──
            toolTip.SetToolTip(this.buildTcpSessionsCheckBox, "Reconstruct TCP sessions for deeper analysis (slower; needed for most modules)");
            toolTip.SetToolTip(this.buildUdpSessionsCheckBox, "Reconstruct UDP sessions for deeper analysis (slower)");

            // ── Modules ──
            toolTip.SetToolTip(this.modulesCheckedListBox, "Toggle individual analysis modules on/off");
            toolTip.SetToolTip(this.modulesGroupBox, "Select which analysis modules to enable during processing");

            // ── Tree view root nodes (designer-defined) ──
            treeViewToolTip(this.modulesTreeView.Nodes["CredentialsNode"], "All extracted credentials (passwords and hashes)");
            treeViewToolTip(this.modulesTreeView.Nodes["CredentialsNode"]?.Nodes["PasswordsNode"], "Extracted cleartext passwords from network traffic");
            treeViewToolTip(this.modulesTreeView.Nodes["CredentialsNode"]?.Nodes["HashesNode"], "Authentication hashes (NTLM, Kerberos, HTTP Digest, etc.)");
            treeViewToolTip(this.modulesTreeView.Nodes["NetworkNode"], "Network-level analysis findings");
            treeViewToolTip(this.modulesTreeView.Nodes["NetworkNode"]?.Nodes["NetworkMapNode"], "Visual network topology map showing connections between hosts");
            treeViewToolTip(this.modulesTreeView.Nodes["NetworkNode"]?.Nodes["SessionsNode"], "Reconstructed TCP/UDP sessions between hosts");
            treeViewToolTip(this.modulesTreeView.Nodes["NetworkNode"]?.Nodes["DnsResponsesNode"], "DNS query-to-IP mappings observed in traffic");
            treeViewToolTip(this.modulesTreeView.Nodes["DataNode"], "Extracted data artifacts");
            treeViewToolTip(this.modulesTreeView.Nodes["DataNode"]?.Nodes["FilesNode"], "Files reconstructed from network streams");
            treeViewToolTip(this.modulesTreeView.Nodes["DataNode"]?.Nodes["VoipCallsNode"], "Detected VoIP/SIP calls with captured RTP streams");

            // ── Tree view root nodes (programmatically added in AddModuleTreeNodes) ──
            treeViewToolTip(this.modulesTreeView.Nodes["DetectionNode"], "Detection engine results — alerts and C2 beacon candidates");
            treeViewToolTip(this.modulesTreeView.Nodes["DetectionNode"]?.Nodes["AlertsNode"], "Payload alerts, anomaly detections, and SMB/ARP alerts");
            treeViewToolTip(this.modulesTreeView.Nodes["DetectionNode"]?.Nodes["BeaconsNode"], "Potential C2 beacon callbacks detected via timing analysis");
            treeViewToolTip(this.modulesTreeView.Nodes["FingerprintsNode"], "TLS, SSH, and application fingerprinting results");
            treeViewToolTip(this.modulesTreeView.Nodes["FingerprintsNode"]?.Nodes["Ja3Node"], "JA3/JA3S TLS client/server fingerprints with known-software lookup");
            treeViewToolTip(this.modulesTreeView.Nodes["FingerprintsNode"]?.Nodes["TlsCertsNode"], "X.509 TLS certificates extracted from handshakes, suspicious flags");
            treeViewToolTip(this.modulesTreeView.Nodes["FingerprintsNode"]?.Nodes["SshNode"], "SSH server host key fingerprints and banner information");
            treeViewToolTip(this.modulesTreeView.Nodes["ProtocolsNode"], "Application-layer protocol metadata and dissections");
            treeViewToolTip(this.modulesTreeView.Nodes["ProtocolsNode"]?.Nodes["HttpNode"], "HTTP request/response metadata (URLs, user-agents, cookies, server headers)");
            treeViewToolTip(this.modulesTreeView.Nodes["ProtocolsNode"]?.Nodes["SmbNode"], "SMB named-pipe, NTLM hash, and lateral movement detections");
            treeViewToolTip(this.modulesTreeView.Nodes["ProtocolsNode"]?.Nodes["DhcpNode"], "DHCP lease activity, rogue DHCP server detection");
            treeViewToolTip(this.modulesTreeView.Nodes["ProtocolsNode"]?.Nodes["ArpNode"], "ARP spoofing and MITM detection alerts");
            treeViewToolTip(this.modulesTreeView.Nodes["AnomaliesNode"], "Statistical anomaly detection — bandwidth spikes, port scans, anomalous traffic");

            // ── Progress bar ──
            toolTip.SetToolTip(this.progressBar, "Processing progress — shows current file and percent complete");

            // ── File analyzing group and related ──
            toolTip.SetToolTip(this.filesAnalyzingGroupBox, "Load, manage, and process PCAP/PCAPNG files");
        }

        /// <summary>
        /// Set a tooltip on a tree node if it exists.
        /// </summary>
        private static void treeViewToolTip(TreeNode node, string text)
        {
            if (node != null)
            {
                node.ToolTipText = text;
            }
        }

    }
}
    
