// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// External Plugin System for BruteShark Studio.
// Allows loading third-party protocol parsers and analysis modules
// from external DLL files at runtime without recompilation.
//
// Plugins implement IModule and/or IPasswordParser from a separate assembly.
// Drop .dll files into the "plugins" folder next to the application.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace PcapAnalyzer
{
    /// <summary>
    /// Manages loading, discovery, and lifecycle of external plugin assemblies.
    /// Plugins are .NET assemblies that export types implementing IModule or IPasswordParser.
    /// </summary>
    public class PluginManager : IDisposable
    {
        private readonly string _pluginsDirectory;
        private readonly List<Assembly> _loadedAssemblies;
        private readonly List<IModule> _externalModules;
        private readonly List<IPasswordParser> _externalParsers;
        private bool _disposed;

        public IReadOnlyList<IModule> ExternalModules => _externalModules.AsReadOnly();
        internal IReadOnlyList<IPasswordParser> ExternalParsers => _externalParsers.AsReadOnly();
        public int LoadedAssemblyCount => _loadedAssemblies.Count;

        public event EventHandler<string> PluginLoaded;
        public event EventHandler<string> PluginLoadFailed;

        public PluginManager(string pluginsDirectory = null)
        {
            _pluginsDirectory = pluginsDirectory ?? Path.Combine(
                AppContext.BaseDirectory, "plugins");
            _loadedAssemblies = new List<Assembly>();
            _externalModules = new List<IModule>();
            _externalParsers = new List<IPasswordParser>();
        }

        /// <summary>
        /// Scan the plugins directory and load all valid plugin assemblies.
        /// Returns the number of plugins successfully loaded.
        /// </summary>
        public int DiscoverAndLoadPlugins()
        {
            if (!Directory.Exists(_pluginsDirectory))
            {
                Directory.CreateDirectory(_pluginsDirectory);
                return 0;
            }

            int loaded = 0;
            var dllFiles = Directory.GetFiles(_pluginsDirectory, "*.dll", SearchOption.TopDirectoryOnly);

            foreach (var dllPath in dllFiles)
            {
                try
                {
                    var assembly = LoadPluginAssembly(dllPath);
                    if (assembly != null)
                    {
                        _loadedAssemblies.Add(assembly);
                        loaded++;

                        // Discover IModule implementations
                        var modules = DiscoverTypes<IModule>(assembly);
                        foreach (var module in modules)
                        {
                            _externalModules.Add(module);
                            PluginLoaded?.Invoke(this, $"Module: {module.Name} (from {Path.GetFileName(dllPath)})");
                        }

                        // Discover IPasswordParser implementations
                        var parsers = DiscoverTypes<IPasswordParser>(assembly);
                        foreach (var parser in parsers)
                        {
                            _externalParsers.Add(parser);
                            PluginLoaded?.Invoke(this, $"Parser: {parser.GetType().Name} (from {Path.GetFileName(dllPath)})");
                        }
                    }
                }
                catch (Exception ex)
                {
                    PluginLoadFailed?.Invoke(this, $"{Path.GetFileName(dllPath)}: {ex.Message}");
                }
            }

            return loaded;
        }

        /// <summary>
        /// Register external modules into an Analyzer instance.
        /// </summary>
        public void RegisterWithAnalyzer(Analyzer analyzer)
        {
            foreach (var module in _externalModules)
            {
                // Hook module events to the analyzer
                module.ParsedItemDetected += (s, e) =>
                    analyzer.GetType().GetEvent("ParsedItemDetected")?
                        .GetRaiseMethod()?.Invoke(analyzer, new object[] { s, e });
            }
        }

        /// <summary>
        /// Get all external password parsers for integration with PasswordsModule.
        /// </summary>
        internal IEnumerable<IPasswordParser> GetExternalParsers()
        {
            return _externalParsers.AsReadOnly();
        }

        private Assembly LoadPluginAssembly(string dllPath)
        {
            // Validate the DLL before loading
            if (!IsValidDotNetAssembly(dllPath))
                return null;

            // Load the assembly into the current domain
            var assemblyName = AssemblyName.GetAssemblyName(dllPath);

            // Check if already loaded
            if (_loadedAssemblies.Any(a => a.FullName == assemblyName.FullName))
                return null;

            var assembly = Assembly.LoadFrom(dllPath);

            // Verify assembly references compatible types
            bool referencesAnalyzer = assembly.GetReferencedAssemblies()
                .Any(r => r.Name == "PcapAnalyzer");

            if (!referencesAnalyzer)
            {
                PluginLoadFailed?.Invoke(this,
                    $"{Path.GetFileName(dllPath)}: does not reference PcapAnalyzer.dll");
                return null;
            }

            return assembly;
        }

        private List<T> DiscoverTypes<T>(Assembly assembly) where T : class
        {
            var results = new List<T>();
            var targetType = typeof(T);

            try
            {
                foreach (var type in assembly.GetTypes())
                {
                    if (targetType.IsAssignableFrom(type) && !type.IsInterface && !type.IsAbstract)
                    {
                        try
                        {
                            var instance = (T)Activator.CreateInstance(type);
                            results.Add(instance);
                        }
                        catch (Exception ex)
                        {
                            PluginLoadFailed?.Invoke(this,
                                $"Failed to instantiate {type.Name}: {ex.Message}");
                        }
                    }
                }
            }
            catch (ReflectionTypeLoadException)
            {
                // Some types failed to load - ignore and continue
            }

            return results;
        }

        private bool IsValidDotNetAssembly(string dllPath)
        {
            try
            {
                AssemblyName.GetAssemblyName(dllPath);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _externalModules.Clear();
                _externalParsers.Clear();
                _loadedAssemblies.Clear();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Example plugin template that developers can use to create external parsers.
    /// Include this as a reference in external plugin projects.
    /// </summary>
    public static class PluginTemplate
    {
        public const string TemplateCode = @"
using System;
using PcapAnalyzer;

namespace MyBruteSharkPlugin
{
    // Example: Custom protocol password parser
    public class MyCustomParser : IPasswordParser
    {
        public NetworkLayerObject Parse(UdpPacket udpPacket) => null;
        public NetworkLayerObject Parse(TcpPacket tcpPacket) => null;
        
        public NetworkLayerObject Parse(TcpSession tcpSession)
        {
            // Your custom parsing logic here
            // Return NetworkPassword, NetworkHash, or null
            return null;
        }
    }
}
";
    }
}
