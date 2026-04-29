using System;

namespace BruteSharkDesktop
{
    /// <summary>
    /// Plugin SDK interface for custom dissector and analysis modules.
    /// Plugins implement this interface to extend BruteShark with custom detection logic.
    /// </summary>
    public interface IPlugin
    {
        /// <summary>Human-readable plugin name.</summary>
        string Name { get; }

        /// <summary>Plugin version.</summary>
        string Version { get; }

        /// <summary>Brief description of what the plugin does.</summary>
        string Description { get; }

        /// <summary>Called when the plugin is loaded. Return true on success.</summary>
        bool Initialize();

        /// <summary>Called when the plugin is unloaded.</summary>
        void Shutdown();
    }
}
