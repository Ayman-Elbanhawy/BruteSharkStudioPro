// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// REST API Server for BruteShark Studio.
// Provides HTTP endpoints for remote analysis and integration:
//  - POST /api/analyze — submit PCAP for analysis  
//  - GET  /api/results — get analysis results as JSON
//  - GET  /api/iocs — get extracted IOCs
//  - GET  /api/report — get HTML forensic report
//  - GET  /api/status — check server status
//
// Built using the lightweight HttpListener (no external dependencies).

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace BruteSharkDesktop
{
    public class RestApiServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly int _port;
        private readonly CancellationTokenSource _cts;
        private Task _listenTask;
        private bool _disposed;

        // Analysis state
        private CommonUi.NetworkContext _lastResults;
        private string _status = "idle";

        public string BaseUrl => $"http://localhost:{_port}";
        public string Status => _status;
        public bool IsRunning => _listenTask != null && !_listenTask.IsCompleted;

        public RestApiServer(int port = 8089)
        {
            _port = port;
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://+:{port}/");
            _cts = new CancellationTokenSource();
        }

        public void Start()
        {
            if (IsRunning) return;

            try
            {
                _listener.Start();
                _status = "running";
                _listenTask = Task.Run(() => ListenLoop(_cts.Token));
            }
            catch (HttpListenerException ex) when (ex.ErrorCode == 5)
            {
                // Access denied — need admin for non-localhost binding
                try
                {
                    _listener.Prefixes.Clear();
                    _listener.Prefixes.Add($"http://localhost:{_port}/");
                    _listener.Start();
                    _status = "running (localhost only)";
                    _listenTask = Task.Run(() => ListenLoop(_cts.Token));
                }
                catch
                {
                    _status = $"failed: {ex.Message}";
                }
            }
            catch (Exception ex)
            {
                _status = $"failed: {ex.Message}";
            }
        }

        public void Stop()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            _status = "stopped";
        }

        public void SetResults(CommonUi.NetworkContext context)
        {
            _lastResults = context;
        }

        private async Task ListenLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var getContextTask = _listener.GetContextAsync();
                    var completed = await Task.WhenAny(getContextTask, Task.Delay(1000, ct));
                    
                    if (completed != getContextTask || ct.IsCancellationRequested)
                        continue;

                    var context = await getContextTask;
                    _ = Task.Run(() => HandleRequest(context));
                }
                catch (OperationCanceledException) { break; }
                catch (HttpListenerException) { break; }
                catch { }
            }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            try
            {
                string path = ctx.Request.Url.AbsolutePath.ToLowerInvariant();
                string response = "";
                string contentType = "application/json";

                switch (path)
                {
                    case "/api/status":
                        response = JsonSerializer.Serialize(new
                        {
                            status = _status,
                            version = "2.0.1",
                            timestamp = DateTime.UtcNow.ToString("o"),
                            modules = _lastResults?.GetType().GetProperties().Length ?? 0
                        });
                        break;

                    case "/api/results":
                        if (_lastResults == null)
                            response = "{\"error\":\"No analysis results available\"}";
                        else
                            response = JsonSerializer.Serialize(new
                            {
                                connections = _lastResults.Connections.Count,
                                hashes = _lastResults.Hashes.Count,
                                dns = _lastResults.DnsMappings.Count,
                                ja3 = _lastResults.Ja3Count,
                                beacons = _lastResults.BeaconCount,
                                detections = _lastResults.DetectionMatches.Count,
                                beacons_list = _lastResults.BeaconResults,
                                detections_list = _lastResults.DetectionMatches
                            }, new JsonSerializerOptions { WriteIndented = true });
                        break;

                    case "/api/iocs":
                        if (_lastResults == null)
                            response = "{\"error\":\"No results\"}";
                        else
                        {
                            var iocs = CommonUi.IocExporter.ExtractIocs(_lastResults);
                            response = JsonSerializer.Serialize(iocs,
                                new JsonSerializerOptions { WriteIndented = true });
                        }
                        break;

                    case "/api/report":
                        if (_lastResults == null)
                            response = "{\"error\":\"No results\"}";
                        else
                        {
                            response = CommonUi.ReportGenerator.GenerateHtmlReport(_lastResults,
                                "BruteShark REST API Report");
                            contentType = "text/html";
                        }
                        break;

                    case "/api/zeek":
                        if (_lastResults == null)
                            response = "{\"error\":\"No results\"}";
                        else
                        {
                            var tmpDir = Path.Combine(Path.GetTempPath(), "bruteshark_zeek_api");
                            CommonUi.ZeekLogExporter.ExportAllZeekLogs(tmpDir, _lastResults);
                            var files = Directory.GetFiles(tmpDir);
                            response = JsonSerializer.Serialize(files);
                        }
                        break;

                    default:
                        response = JsonSerializer.Serialize(new
                        {
                            name = "BruteShark Studio REST API",
                            version = "2.0.1",
                            endpoints = new[]
                            {
                                "GET /api/status  — server status",
                                "GET /api/results — analysis results summary",
                                "GET /api/iocs    — indicators of compromise",
                                "GET /api/report  — HTML forensic report",
                                "GET /api/zeek    — Zeek-format logs"
                            }
                        }, new JsonSerializerOptions { WriteIndented = true });
                        contentType = "application/json";
                        break;
                }

                byte[] buffer = Encoding.UTF8.GetBytes(response);
                ctx.Response.ContentType = contentType;
                ctx.Response.ContentLength64 = buffer.Length;
                ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
            }
            catch { }
            finally
            {
                try { ctx.Response.OutputStream.Close(); } catch { }
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Stop();
                _listener?.Close();
                _cts?.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
