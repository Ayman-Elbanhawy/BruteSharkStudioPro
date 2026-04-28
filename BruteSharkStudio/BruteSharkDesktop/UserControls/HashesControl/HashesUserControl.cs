using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using PcapAnalyzer;
using System.IO;

namespace BruteSharkDesktop
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // This control owns the desktop hash workflow: review extracted hashes,
    // export them in Hashcat format, and optionally run Hashcat immediately.
    public partial class HashesUserControl : UserControl
    {
        private CommonUi.NetworkContext _networkContext;
        private GenericTableUserControl _hashesTableUserControl; 

        public int HashesCount => _hashesTableUserControl.ItemsCount;

        public HashesUserControl(CommonUi.NetworkContext networkContext)
        {
            InitializeComponent();
            _networkContext = networkContext;

            // Reuse the generic table control so the hashes view inherits the
            // existing filtering/sorting behavior used elsewhere in the desktop UI.
            this._hashesTableUserControl = new GenericTableUserControl();
            _hashesTableUserControl.Dock = DockStyle.Fill;
            _hashesTableUserControl.SetTableDataType(typeof(PcapAnalyzer.NetworkHash));
            _hashesTableUserControl.SelectionChanged += OnSelectionChanged;
            this.mainSplitContainer.Panel1.Controls.Clear();
            this.mainSplitContainer.Panel1.Controls.Add(_hashesTableUserControl);
        }

        public void AddHash(PcapAnalyzer.NetworkHash networkHash)
        {
            // TODO: use network context hashes as the only data source
            _hashesTableUserControl.AddDataToTable(networkHash);
            _networkContext.Hashes.Add(networkHash);

            if (!this.hashesComboBox.Items.Contains(networkHash.HashType))
            {
                this.hashesComboBox.Items.Add(networkHash.HashType);
            }
        }

        private void OnSelectionChanged(object sender, EventArgs e)
        {
            var hash = _hashesTableUserControl.SelectedRowBoundItem;

            if (hash != null)
            {
                this.hashDataRichTextBox.Clear();

                foreach (PropertyDescriptor descriptor in TypeDescriptor.GetProperties(hash))
                {
                    string name = descriptor.Name;
                    object value = descriptor.GetValue(hash);
                    this.hashDataRichTextBox.Text += ($"{name} = {value}{Environment.NewLine}");
                }
            }
        }

        private void CreateHashcatFileButton_Click(object sender, EventArgs e)
        {
            var selectedHashType = this.hashesComboBox.SelectedItem;

            try
            {
                ValidateHashcatExportInputs(selectedHashType);
                var outputFilePath = CreateHashcatInputFile(selectedHashType.ToString(), this.selectedFolderTextBox.Text);
                MessageBox.Show($"Hashes exported: {outputFilePath}");
            }
            catch (BruteForce.NotSupportedHashcatHash ex)
            {
                MessageBox.Show($"Hashcat does not support this hash type: {ex.Message}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export hashes: {ex.Message}");
            }
        }

        private async void CrackWithHashcatButton_Click(object sender, EventArgs e)
        {
            var selectedHashType = this.hashesComboBox.SelectedItem;

            try
            {
                ValidateHashcatExportInputs(selectedHashType);

                if (!File.Exists(this.wordlistTextBox.Text))
                {
                    MessageBox.Show("No valid Hashcat wordlist selected");
                    return;
                }

                var selectedHashes = GetHashesByType(selectedHashType.ToString()).ToList();
                // All hashes in the selected view share one display type, so the
                // first item is enough to resolve the correct Hashcat mode.
                var mode = BruteForce.HashcatRunner.GetHashcatMode(
                    CommonUi.Casting.CastAnalyzerHashToBruteForceHash(selectedHashes.First()));
                var hashFilePath = CreateHashcatInputFile(selectedHashType.ToString(), this.selectedFolderTextBox.Text);
                var crackedDir = Path.Combine(this.selectedFolderTextBox.Text, "Cracked Hashes");
                Directory.CreateDirectory(crackedDir);
                var outputFilePath = CommonUi.Exporting.GetUniqueFilePath(Path.Combine(
                    crackedDir,
                    $"Brute Shark - {selectedHashType} Cracked.txt"));

                this.crackWithHashcatButton.Enabled = false;
                this.crackWithHashcatButton.Text = "Cracking...";

                var result = await Task.Run(() => BruteForce.HashcatRunner.CrackHashFile(
                    this.hashcatPathTextBox.Text,
                    mode,
                    hashFilePath,
                    this.wordlistTextBox.Text,
                    outputFilePath,
                    this.hashcatExtraArgsTextBox.Text));

                var message = $"Hashcat finished with exit code {result.ExitCode}.{Environment.NewLine}" +
                              $"Mode: {result.HashcatMode}{Environment.NewLine}" +
                              $"Hash file: {result.HashFilePath}{Environment.NewLine}" +
                              $"Output file: {result.OutputFilePath}";

                if (!string.IsNullOrWhiteSpace(result.ShowOutput))
                {
                    message += $"{Environment.NewLine}{Environment.NewLine}Cracked hashes:{Environment.NewLine}{result.ShowOutput}";
                }

                if (!string.IsNullOrWhiteSpace(result.StandardError))
                {
                    message += $"{Environment.NewLine}{Environment.NewLine}Hashcat errors:{Environment.NewLine}{result.StandardError}";
                }

                MessageBox.Show(message);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to crack hashes with Hashcat: {ex.Message}");
            }
            finally
            {
                this.crackWithHashcatButton.Enabled = true;
                this.crackWithHashcatButton.Text = "Crack with Hashcat";
            }
        }

        private void ChoseDirectoryButton_Click(object sender, EventArgs e)
        {
            var selecetDirectoryDialog = new FolderBrowserDialog();

            if (selecetDirectoryDialog.ShowDialog() == DialogResult.OK)
            {
                this.selectedFolderTextBox.Text = selecetDirectoryDialog.SelectedPath;
            }
        }

        private void ChoseHashcatButton_Click(object sender, EventArgs e)
        {
            var openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Executables|*.exe|All files|*.*";

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                this.hashcatPathTextBox.Text = openFileDialog.FileName;
            }
        }

        private void ChoseWordlistButton_Click(object sender, EventArgs e)
        {
            var openFileDialog = new OpenFileDialog();

            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                this.wordlistTextBox.Text = openFileDialog.FileName;
            }
        }

        private void ValidateHashcatExportInputs(object selectedHashType)
        {
            if (_hashesTableUserControl.ItemsCount == 0)
            {
                throw new InvalidOperationException("No hashes found");
            }
            if (selectedHashType == null || selectedHashType.ToString() == string.Empty)
            {
                throw new InvalidOperationException("No hash type selected");
            }
            if (!Directory.Exists(this.selectedFolderTextBox.Text))
            {
                throw new InvalidOperationException("No valid output directory selected");
            }
        }

        private IEnumerable<PcapAnalyzer.NetworkHash> GetHashesByType(string hashType)
        {
            return _hashesTableUserControl.Items
                .Cast<PcapAnalyzer.NetworkHash>()
                .Where(h => h.HashType == hashType);
        }

        private string CreateHashcatInputFile(string hashType, string outputDirectoryPath)
        {
            // Export the currently selected hash family to a dedicated file so it
            // can be reused outside the GUI or passed straight into Hashcat.
            var hashesToExport = GetHashesByType(hashType)
                .Select(h => BruteForce.Utilities.ConvertToHashcatFormat(
                    CommonUi.Casting.CastAnalyzerHashToBruteForceHash(h)));

            var outputFilePath = CommonUi.Exporting.GetUniqueFilePath(Path.Combine(
                outputDirectoryPath,
                $"Brute Shark - {hashType} Hashcat Export.txt"));

            using (var streamWriter = new StreamWriter(outputFilePath, true))
            {
                foreach (var hash in hashesToExport)
                {
                    streamWriter.WriteLine(hash);
                }
            }

            return outputFilePath;
        }
        
    }
}
