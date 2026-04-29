using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

namespace BruteSharkDesktop
{
    public static class PluginLoader
    {
        public static List<IPlugin> LoadPlugins(string pluginsDir)
        {
            var plugins = new List<IPlugin>();
            if (!Directory.Exists(pluginsDir)) return plugins;
            foreach (var dll in Directory.GetFiles(pluginsDir, "*.dll"))
            {
                try
                {
                    var asm = Assembly.LoadFrom(dll);
                    foreach (var t in asm.GetTypes().Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsInterface && !t.IsAbstract))
                    {
                        if (Activator.CreateInstance(t) is IPlugin p && p.Initialize()) plugins.Add(p);
                    }
                }
                catch { }
            }
            return plugins;
        }
    }
}
