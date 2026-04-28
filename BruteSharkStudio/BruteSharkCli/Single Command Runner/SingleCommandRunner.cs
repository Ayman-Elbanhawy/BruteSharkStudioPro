using System;
using System.Collections.Generic;
using System.Text;
using PcapProcessor;
using PcapAnalyzer;
using System.IO;
using System.Linq;
using CommandLine;
using CommonUi;
using System.Reflection;

namespace BruteSharkCli
{
    class SingleCommandRunner
    {
        private SingleCommandFlags _cliFlags;
        private List<string> _files;
        private CommonUi.NetworkContext _networkContext;
        private HashSet<PcapAnalyzer.NetworkFile> _extractedFiles;
        private HashSet<PcapAnalyzer.NetworkPassword> _passwords;
        private HashSet<CommonUi.VoipCall> _voipCalls;

        private Sniffer _sniffer; 
        private PcapProcessor.Processor _processor;
        private PcapAnalyzer.Analyzer _analyzer;

        // Phase 3: Detection and intelligence
        private DetectionRuleEngine _detectionEngine;
        private BeaconDetectionModule _beaconModule;

        // Phase 4: Flow aggregation, timeline, and YARA
        private FlowAggregationEngine _flowEngine;
        private TimelineReconstructor _timeline;
        private YaraRuleLoader _yaraLoader;

        private readonly Dictionary<string, string> CliModulesNamesToAnalyzerNames = new Dictionary<string, string> {
            { "FileExtracting" , "File Extracting"},
            { "NetworkMap", "Network Map" },
            { "Credentials" ,"Credentials Extractor (Passwords, Hashes)"},
            { "Voip" ,"Voip Calls"},
            { "DNS", "DNS"},
            { "JA3", "JA3/JA4 TLS Fingerprinting"},
            { "BeaconDetection", "C2 Beacon Detection"}
        };

        public SingleCommandRunner(Analyzer analyzer, Processor processor, Sniffer sniffer, string[] args)
        {
            _sniffer = sniffer;
            _analyzer = analyzer;
            _processor = processor;
            _files = new List<string>();

            _networkContext = new NetworkContext();
            _passwords = new HashSet<NetworkPassword>();
            _extractedFiles = new HashSet<NetworkFile>();
            _voipCalls = new HashSet<CommonUi.VoipCall>();

            _analyzer.ParsedItemDetected += OnParsedItemDetected;
            _analyzer.UpdatedItemProprertyDetected += UpdatedPropertyInItemDetected;

            // Phase 3: Initialize detection engine
            _detectionEngine = new DetectionRuleEngine();
            _beaconModule = new BeaconDetectionModule();

            // Wire detection engine and beacon module to packet events
            _processor.UdpPacketArived += (s, e) => _detectionEngine.EvaluatePacket(
                CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _processor.TcpPacketArived += (s, e) => _detectionEngine.EvaluatePacket(
                CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));
            _processor.UdpPacketArived += (s, e) => _beaconModule.Analyze(
                CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _processor.TcpPacketArived += (s, e) => _beaconModule.Analyze(
                CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));

            // Phase 4: Initialize flow aggregation, timeline, and YARA loader
            _flowEngine = new FlowAggregationEngine();
            _timeline = new TimelineReconstructor();
            _yaraLoader = new YaraRuleLoader();

            // Wire flow engine to packet pipeline
            _processor.UdpPacketArived += (s, e) => _flowEngine.Analyze(
                CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
            _processor.TcpPacketArived += (s, e) => _flowEngine.Analyze(
                CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));

            // Auto-load YARA rules from the rules directory
            var rulesDir = Path.Combine(AppContext.BaseDirectory, "rules");
            if (Directory.Exists(rulesDir))
            {
                int loaded = _yaraLoader.LoadAndRegister(rulesDir, _detectionEngine);
                if (loaded > 0)
                    CliPrinter.Info($"Loaded {loaded} YARA rules from {rulesDir}");
            }

            _processor.UdpSessionArrived += (s, e) => OnSessionArrived(e.UdpSession as PcapProcessor.INetworkSession<NetworkPacket>);
            _processor.TcpSessionArrived += (s, e) => OnSessionArrived(e.TcpSession as PcapProcessor.INetworkSession<NetworkPacket>);
            _processor.ProcessingFinished += (s, e) => this.ExportResults();
            _processor.FileProcessingStatusChanged += (s, e) => this.PrintFileStatusUpdate(s, e);

            // This is done to catch Ctrl + C key press by the user.
            Console.CancelKeyPress += (s, e) => {this.ExportResults(); Environment.Exit(0);};

            // Parse user arguments.
            CommandLine.Parser.Default.ParseArguments<SingleCommandFlags>(args).WithParsed<SingleCommandFlags>((cliFlags) => _cliFlags = cliFlags);
        }

        private void OnSessionArrived(PcapProcessor.INetworkSession<NetworkPacket> session)
        {
            _networkContext.NetworkSessions.Add(session);
        }

        public void Run()
        {
            try
            {
                SetupRun();

                if (_cliFlags.CaptureDevice != null)
                {
                    SetupSniffer();

                    CliPrinter.Info(_sniffer.PromisciousMode ?
                        $"Started analyzing packets from {_cliFlags.CaptureDevice} device (Promiscuous mode) - Press Ctrl + C to stop" :
                        $"Started analyzing packets from {_cliFlags.CaptureDevice} device - Press Ctrl + C to stop");
                    
                    _sniffer.StartSniffing(new System.Threading.CancellationToken());
                }
                else 
                {
                    CliPrinter.Info($"Start analyzing {_files.Count} files");
                    _processor.ProcessPcaps(_files);
                }
            }
            catch (Exception ex)
            {
                CliPrinter.Error(ex);
            }
        }

        private void SetupSniffer()
        {
            if (!_sniffer.AvailiableDevicesNames.Contains(_cliFlags.CaptureDevice))
            {
                CliPrinter.Error($"No such device: {_cliFlags.CaptureDevice}");
                Environment.Exit(0);
            }

            _sniffer.SelectedDeviceName = _cliFlags.CaptureDevice;

            if (_cliFlags.PromisciousMode)
            {
                _sniffer.PromisciousMode = true;
            }

            if (_cliFlags.CaptrueFilter != null)
            {
                if (!Sniffer.CheckCaptureFilter(_cliFlags.CaptrueFilter))
                {
                    CliPrinter.Error($"The capture filter: {_cliFlags.CaptrueFilter} is not a valid filter - filters must be in a bpf format");
                    Environment.Exit(0);
                }

                _sniffer.Filter = _cliFlags.CaptrueFilter;
            }
        }

        private void PrintFileStatusUpdate(object sender, FileProcessingStatusChangedEventArgs e)
        {
            if (e.Status == FileProcessingStatus.Started)
            {
                CliPrinter.Info($"Start processing file : {Path.GetFileName(e.FilePath)}");
            }
            else if (e.Status == FileProcessingStatus.Finished)
            {
                CliPrinter.Info($"Finished processing file : {Path.GetFileName(e.FilePath)}");
            }
            else if (e.Status == FileProcessingStatus.Faild)
            {
                CliPrinter.Error($"Failed to process file : {Path.GetFileName(e.FilePath)}");
            }
        }

        private void SetupRun()
        {
            // That can happen when the user enter version \ help command, exit gracefully.
            if (_cliFlags is null)
            {
                Environment.Exit(0);
            }

            // Load modules.
            if (_cliFlags?.Modules?.Any() == true)
            {
                LoadModules(ParseCliModuleNames(_cliFlags.Modules));
            }
            else
            {
                throw new Exception("No modules selected");
            }

            if (_cliFlags.InputFiles.Count() != 0 && _cliFlags.InputDir != null)
            {
                throw new Exception("Only one of the arguments -i and -d can be presented in a single command mode run");
            }
            else if (_cliFlags.InputFiles.Count() != 0)
            {
                foreach (string filePath in _cliFlags.InputFiles)
                {
                    AddFile(filePath);
                }
            }
            else if (_cliFlags.InputDir != null)
            {
                VerifyDir(_cliFlags.InputDir);
            }
        }

        private void LoadModules(List<string> modules)
        {
            foreach (string m in modules)
            {
                _analyzer.AddModule(m);
            }
        }

        private List<string> ParseCliModuleNames(IEnumerable<string> modules)
        {
            var analyzerModulesToLoad = new List<string>();

            foreach (var cliModuleName in modules)
            {
                string analyzerModuleName = CliModulesNamesToAnalyzerNames.GetValueOrDefault(cliModuleName, defaultValue: null);

                if (analyzerModuleName != null)
                {
                    analyzerModulesToLoad.Add(analyzerModuleName);
                }
            }

            return analyzerModulesToLoad;
        }

        private void VerifyDir(string dirPath)
        {
            FileAttributes attrs = File.GetAttributes(dirPath);
            if ((attrs & FileAttributes.Directory) == FileAttributes.Directory)
            {
                DirectoryInfo dir = new DirectoryInfo(dirPath);
                foreach (var file in dir.GetFiles("*.*"))
                {
                    AddFile(file.FullName);
                }
            }
            else
            {
                throw new IOException($"{dirPath} is not a valid directory path");
            }
        }

        private void ExportResults()
        {
            if (_cliFlags.OutputDir != null)
            { 
                if (_networkContext.Connections.Any())
                {
                    var networkMapFilePath = CommonUi.Exporting.ExportNetworkMap(_cliFlags.OutputDir, _networkContext.Connections);
                    CliPrinter.Info($"Successfully exported network map to json file: {networkMapFilePath}");
                    var nodesDataFilePath = CommonUi.Exporting.ExportNetworkNodesData(_cliFlags.OutputDir, _networkContext.GetAllNodes());
                    CliPrinter.Info($"Successfully exported network nodes data to json file: {nodesDataFilePath}");
                }
                if (_networkContext.Hashes.Any())
                {
                    Utilities.ExportHashes(_cliFlags.OutputDir, _networkContext.Hashes);
                    CliPrinter.Info($"Successfully exported hashes");
                }
                if (_files.Any())
                {
                    var dirPath = CommonUi.Exporting.ExportFiles(_cliFlags.OutputDir, _extractedFiles);
                    CliPrinter.Info($"Successfully exported extracted files to: {dirPath}");
                }
                if (_networkContext.DnsMappings.Any())
                {
                    var dnsFilePath = CommonUi.Exporting.ExportDnsMappings(_cliFlags.OutputDir, _networkContext.DnsMappings);
                    CliPrinter.Info($"Successfully exported DNS mappings to file: {dnsFilePath}");
                }
				if(_voipCalls.Any())
                {
                   var dirPath = CommonUi.Exporting.ExportVoipCalls(_cliFlags.OutputDir, _voipCalls);
                    CliPrinter.Info($"Successfully exported Voip calls extracted to: {dirPath}");
                }

                // Phase 3: Export JA3 fingerprints
                if (_networkContext.Ja3Fingerprints.Any())
                {
                    var ja3Path = CommonUi.Exporting.ExportJa3Fingerprints(_cliFlags.OutputDir, _networkContext.Ja3Fingerprints);
                    if (ja3Path != null)
                        CliPrinter.Info($"Successfully exported JA3 fingerprints to: {ja3Path}");
                }

                // Phase 3: Export beacon detection results
                if (_networkContext.BeaconResults.Any())
                {
                    var beaconPath = CommonUi.Exporting.ExportBeaconResults(_cliFlags.OutputDir, _networkContext.BeaconResults);
                    if (beaconPath != null)
                        CliPrinter.Info($"⚠ Successfully exported beacon detections to: {beaconPath}");
                }

                // Phase 3: Export detection rule matches
                if (_networkContext.DetectionMatches.Any())
                {
                    var matchesPath = CommonUi.Exporting.ExportRuleMatches(_cliFlags.OutputDir, _networkContext.DetectionMatches);
                    if (matchesPath != null)
                        CliPrinter.Info($"Successfully exported detection matches to: {matchesPath}");
                }

                // Phase 4: Export IOCs in STIX/CSV formats
                var iocs = CommonUi.IocExporter.ExtractIocs(_networkContext);
                if (iocs.Any())
                {
                    var csvPath = CommonUi.IocExporter.ExportToFile(_cliFlags.OutputDir, iocs, "csv");
                    CliPrinter.Info($"Successfully exported IOCs (CSV) to: {csvPath}");
                    var stixPath = CommonUi.IocExporter.ExportToFile(_cliFlags.OutputDir, iocs, "stix");
                    CliPrinter.Info($"Successfully exported IOCs (STIX 2.0) to: {stixPath}");
                }

                // Phase 4: Export HTML forensic report
                if (_networkContext.Connections.Any() || _networkContext.Hashes.Any() || _networkContext.DetectionMatches.Any())
                {
                    var reportPath = CommonUi.ReportGenerator.ExportReport(_cliFlags.OutputDir, _networkContext);
                    CliPrinter.Info($"Successfully exported HTML report to: {reportPath}");
                }

                // Phase 4: Export flow statistics
                var flowStats = _flowEngine.GetStatistics();
                var flowStatsPath = Exporting.GetUniqueFilePath(Path.Combine(_cliFlags.OutputDir, "BruteShark Flow Statistics.json"));
                File.WriteAllText(flowStatsPath, Exporting.GetIndentdJson(new[] { flowStats }));
                CliPrinter.Info($"Successfully exported flow statistics to: {flowStatsPath}");

                // Phase 4: Export forensic timeline
                var timelineReport = _timeline.GenerateTextReport();
                var timelinePath = Exporting.GetUniqueFilePath(Path.Combine(_cliFlags.OutputDir, "BruteShark Forensic Timeline.txt"));
                File.WriteAllText(timelinePath, timelineReport);
                CliPrinter.Info($"Successfully exported forensic timeline to: {timelinePath}");

                // Phase 5: Export Zeek-format logs
                var zeekDir = CommonUi.ZeekLogExporter.ExportAllZeekLogs(_cliFlags.OutputDir, _networkContext);
                CliPrinter.Info($"Successfully exported Zeek-format logs to: {zeekDir}");

                // Phase 5: Export PDF forensic report
                var pdfPath = CommonUi.PdfReportGenerator.ExportPdfReport(_cliFlags.OutputDir, _networkContext);
                CliPrinter.Info($"Successfully exported PDF report to: {pdfPath}");
            }

            if (_cliFlags.HashcatWordlist != null)
            {
                if (_cliFlags.OutputDir == null)
                {
                    CliPrinter.Error("Hashcat cracking requires -o/--output so generated hash and cracked-output files can be stored.");
                }
                else if (!_networkContext.Hashes.Any())
                {
                    CliPrinter.Info("No hashes found for Hashcat cracking");
                }
                else
                {
                    Utilities.CrackHashesWithHashcat(
                        _cliFlags.OutputDir,
                        _networkContext.Hashes,
                        _cliFlags.HashcatPath,
                        _cliFlags.HashcatWordlist,
                        _cliFlags.HashcatExtraArguments);
                }
            }

            CliPrinter.Info("BruteShark finished processing");
        }

        private void AddFile(string filePath)
        {
            if (File.Exists(filePath))
            {
                _files.Add(filePath);
            }
            else
            {
                CliPrinter.Error($"File does not exist - {filePath}");
            }
        }

        private void UpdatedPropertyInItemDetected(object sender, UpdatedPropertyInItemeventArgs e)
        {
            if (e.ParsedItem is PcapAnalyzer.VoipCall)
            {
                var voipCall = CommonUi.Casting.CastAnalyzerVoipCallToPresentationVoipCall(e.ParsedItem as PcapAnalyzer.VoipCall);

                if (_voipCalls.Contains(voipCall))
                {
                    voipCall.GetType()
                        .GetProperty(e.PropertyChanged.Name, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Instance)
                        .SetValue(_voipCalls
                            .Where(c => c.Equals(voipCall))
                            .FirstOrDefault(), e.NewPropertyValue);

                    if (e.PropertyChanged.Name == "CallState" || e.PropertyChanged.Name == "RTPPort")
                    {
                        PrintUpdatedItem(_voipCalls.Where(c => c.Equals(voipCall)).First(), e.PropertyChanged.Name);
                    }
                }
            }
        }

        private void OnParsedItemDetected(object sender, ParsedItemDetectedEventArgs e)
        {
            if (e.ParsedItem is PcapAnalyzer.NetworkPassword)
            {
                if (_passwords.Add(e.ParsedItem as PcapAnalyzer.NetworkPassword))
                {
                    PrintDetectedItem(e.ParsedItem);
                }
            }
            else if (e.ParsedItem is PcapAnalyzer.NetworkHash)
            {
                if (_networkContext.Hashes.Add(e.ParsedItem as PcapAnalyzer.NetworkHash))
                {
                    PrintDetectedItem(e.ParsedItem);
                }
            }
            else if (e.ParsedItem is PcapAnalyzer.NetworkFile)
            {
                if (_extractedFiles.Add(e.ParsedItem as PcapAnalyzer.NetworkFile))
                {
                    PrintDetectedItem(e.ParsedItem);
                }
            }
            else if (e.ParsedItem is PcapAnalyzer.NetworkConnection)
            {
                var networkConnection = e.ParsedItem as NetworkConnection;
                _networkContext.HandleNetworkConection(networkConnection);
            }
            else if (e.ParsedItem is PcapAnalyzer.VoipCall)
            {
                var voipCall = e.ParsedItem as PcapAnalyzer.VoipCall;
                CommonUi.VoipCall callPresentation = CommonUi.Casting.CastAnalyzerVoipCallToPresentationVoipCall(voipCall);
                PrintDetectedItem(callPresentation);
                _voipCalls.Add(callPresentation);
			}
            else if (e.ParsedItem is PcapAnalyzer.DnsNameMapping)
            {
                if (_networkContext.HandleDnsNameMapping(e.ParsedItem as DnsNameMapping))
                {
                    PrintDetectedItem(e.ParsedItem);
                }
            }
            else if (e.ParsedItem is PcapAnalyzer.Ja3Fingerprint)
            {
                var ja3 = e.ParsedItem as PcapAnalyzer.Ja3Fingerprint;
                _networkContext.HandleJa3Fingerprint(ja3);
                PrintDetectedItem(e.ParsedItem);
            }
            else if (e.ParsedItem is PcapAnalyzer.BeaconResult)
            {
                var beacon = e.ParsedItem as PcapAnalyzer.BeaconResult;
                _networkContext.AddBeaconResult(beacon);
                CliPrinter.WriteLine(ConsoleColor.Red, $"⚠ BEACON: {e.ParsedItem}");
            }
        }

        private void PrintDetectedItem(object item)
        {
            CliPrinter.WriteLine(ConsoleColor.Blue, $"Found: {item}");
        }

        private void PrintUpdatedItem(object item, string propertyUpdatedName)
        {
            CliPrinter.WriteLine(ConsoleColor.Blue, $"Updated {propertyUpdatedName} for: {item}");
        }

    }
}
