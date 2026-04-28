using BruteForce;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;

namespace PcapAnalyzerTest
{
    [TestClass]
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // These tests lock down the Hashcat mode mapping and executable discovery
    // behavior that the desktop and CLI rely on.
    public class HashcatRunnerTest
    {
        [TestMethod]
        public void GetHashcatMode_ReturnsExpectedModes()
        {
            Assert.AreEqual(11400, HashcatRunner.GetHashcatMode(new HttpDigestHash()));
            Assert.AreEqual(16400, HashcatRunner.GetHashcatMode(new CramMd5Hash()));
            Assert.AreEqual(5500, HashcatRunner.GetHashcatMode(new NtlmHash { NtHash = new string('a', 24) }));
            Assert.AreEqual(5600, HashcatRunner.GetHashcatMode(new NtlmHash { NtHash = new string('a', 25) }));
            Assert.AreEqual(7500, HashcatRunner.GetHashcatMode(new KerberosHash()));
            Assert.AreEqual(18200, HashcatRunner.GetHashcatMode(new KerberosAsRepHash { Etype = 23 }));
            Assert.AreEqual(13100, HashcatRunner.GetHashcatMode(new KerberosTgsRepHash { Etype = 23 }));
            Assert.AreEqual(19600, HashcatRunner.GetHashcatMode(new KerberosTgsRepHash { Etype = 17 }));
            Assert.AreEqual(19700, HashcatRunner.GetHashcatMode(new KerberosTgsRepHash { Etype = 18 }));
        }

        [TestMethod]
        public void ResolveHashcatPath_UsesProvidedPath()
        {
            Assert.AreEqual(@"C:\Tools\hashcat\hashcat.exe", HashcatRunner.ResolveHashcatPath(@"C:\Tools\hashcat\hashcat.exe"));
        }

        [TestMethod]
        public void ResolveHashcatPath_UsesPathExecutable()
        {
            var originalPath = Environment.GetEnvironmentVariable("PATH");
            var tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDirectory);

            try
            {
                var hashcatPath = Path.Combine(tempDirectory, "hashcat.exe");
                File.WriteAllText(hashcatPath, string.Empty);
                Environment.SetEnvironmentVariable("PATH", tempDirectory + Path.PathSeparator + originalPath);

                Assert.AreEqual(hashcatPath, HashcatRunner.ResolveHashcatPath("hashcat"));
            }
            finally
            {
                Environment.SetEnvironmentVariable("PATH", originalPath);
                Directory.Delete(tempDirectory, true);
            }
        }
    }
}
