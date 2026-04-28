using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace BruteForce
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // This helper keeps all Hashcat process integration in one place so the
    // GUI and CLI can share the same executable lookup and cracking flow.
    public class HashcatRunResult
    {
        public int ExitCode { get; set; }
        public string StandardOutput { get; set; }
        public string StandardError { get; set; }
        public string ShowOutput { get; set; }
        public string HashFilePath { get; set; }
        public string OutputFilePath { get; set; }
        public int HashcatMode { get; set; }
    }

    public static class HashcatRunner
    {
        private static readonly object _initLock = new object();
        private static string _cachedWorkingDir = null;

        /// <summary>
        /// Prepares a writable working directory for hashcat by copying its
        /// required runtime assets (OpenCL, modules, rules) from the install
        /// folder to a user-writable location. This avoids "Permission denied"
        /// errors when hashcat is installed under Program Files.
        /// </summary>
        public static string EnsureWritableWorkingDir(string hashcatExePath)
        {
            if (_cachedWorkingDir != null && Directory.Exists(_cachedWorkingDir))
                return _cachedWorkingDir;

            lock (_initLock)
            {
                if (_cachedWorkingDir != null) return _cachedWorkingDir;

                var hashcatDir = Path.GetDirectoryName(hashcatExePath);
                var writableDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "BruteSharkStudio", "HashcatRuntime");

                // Copy required runtime folders if not already present
                CopyHashcatRuntimeAssets(hashcatDir, writableDir);

                _cachedWorkingDir = writableDir;
                return writableDir;
            }
        }

        private static void CopyHashcatRuntimeAssets(string sourceDir, string targetDir)
        {
            var foldersToCopy = new[] { "OpenCL", "modules", "rules" };
            var filesToCopy = new[] { "hashcat.hctune", "hashcat.hcstat2" };

            foreach (var folder in foldersToCopy)
            {
                var src = Path.Combine(sourceDir, folder);
                var dst = Path.Combine(targetDir, folder);
                if (Directory.Exists(src) && !Directory.Exists(dst))
                {
                    CopyDirectoryRecursive(src, dst);
                }
            }

            foreach (var file in filesToCopy)
            {
                var src = Path.Combine(sourceDir, file);
                var dst = Path.Combine(targetDir, file);
                if (File.Exists(src) && !File.Exists(dst))
                {
                    Directory.CreateDirectory(targetDir);
                    File.Copy(src, dst, overwrite: false);
                }
            }
        }

        private static void CopyDirectoryRecursive(string sourceDir, string targetDir)
        {
            Directory.CreateDirectory(targetDir);
            foreach (var file in Directory.GetFiles(sourceDir))
            {
                var dest = Path.Combine(targetDir, Path.GetFileName(file));
                if (!File.Exists(dest))
                    File.Copy(file, dest);
            }
            foreach (var dir in Directory.GetDirectories(sourceDir))
            {
                CopyDirectoryRecursive(dir, Path.Combine(targetDir, Path.GetFileName(dir)));
            }
        }
        // Prefer an explicit path first, then the installer-bundled Hashcat
        // folder, and finally a PATH lookup. Returning a full path lets the
        // process runner set Hashcat's working directory correctly so it can
        // find its sibling OpenCL/modules/rules folders.
        public static string ResolveHashcatPath(string hashcatPath = null)
        {
            if (!string.IsNullOrWhiteSpace(hashcatPath))
            {
                if (File.Exists(hashcatPath))
                {
                    return Path.GetFullPath(hashcatPath);
                }

                if (!hashcatPath.Contains(Path.DirectorySeparatorChar.ToString()) &&
                    !hashcatPath.Contains(Path.AltDirectorySeparatorChar.ToString()))
                {
                    return FindExecutableOnPath(hashcatPath) ?? hashcatPath;
                }

                return hashcatPath;
            }

            var bundledHashcatPath = Path.Combine(AppContext.BaseDirectory, "Hashcat", "hashcat.exe");

            if (File.Exists(bundledHashcatPath))
            {
                return bundledHashcatPath;
            }

            return FindExecutableOnPath("hashcat.exe") ?? "hashcat";
        }

        // Map extracted BruteShark hash models to the Hashcat mode numbers that
        // are needed for export and cracking.
        public static int GetHashcatMode(Hash hash)
        {
            if (hash is HttpDigestHash)
            {
                return 11400;
            }
            if (hash is CramMd5Hash)
            {
                return 16400;
            }
            if (hash is NtlmHash ntlmHash)
            {
                if (ntlmHash.NtHash.Length == 24)
                {
                    return 5500;
                }
                if (ntlmHash.NtHash.Length > 24)
                {
                    return 5600;
                }

                throw new NotSupportedHashcatHash("NTLM hash has nt part shorter than 24 chars");
            }
            if (hash is KerberosHash)
            {
                return 7500;
            }
            if (hash is KerberosAsRepHash asRepHash)
            {
                if (asRepHash.Etype == 23)
                {
                    return 18200;
                }

                throw new NotSupportedHashcatHash($"Kerberos AS-REP Etype {asRepHash.Etype} is not supported by Hashcat");
            }
            if (hash is KerberosTgsRepHash tgsRepHash)
            {
                if (tgsRepHash.Etype == 23)
                {
                    return 13100;
                }
                if (tgsRepHash.Etype == 17)
                {
                    return 19600;
                }
                if (tgsRepHash.Etype == 18)
                {
                    return 19700;
                }

                throw new NotSupportedHashcatHash($"Kerberos TGS-REP Etype {tgsRepHash.Etype} is not supported by Hashcat");
            }

            throw new NotSupportedHashcatHash("Hash type not supported");
        }

        public static HashcatRunResult CrackHashFile(
            string hashcatPath,
            int hashcatMode,
            string hashFilePath,
            string wordlistPath,
            string outputFilePath,
            string extraArguments = null)
        {
            if (!File.Exists(hashFilePath))
            {
                throw new FileNotFoundException("Hashcat hash file does not exist", hashFilePath);
            }
            if (!File.Exists(wordlistPath))
            {
                throw new FileNotFoundException("Hashcat wordlist file does not exist", wordlistPath);
            }

            var hashcatExecutable = ResolveHashcatPath(hashcatPath);

            // Hashcat writes potfile/session files to its working directory.
            // Since the install dir (Program Files) is write-protected, use a temp dir.
            var sessionDir = Path.Combine(Path.GetTempPath(), "BruteSharkStudio", "hashcat_sessions");
            Directory.CreateDirectory(sessionDir);
            var sessionName = $"bruteshark_{hashcatMode}_{Path.GetFileNameWithoutExtension(hashFilePath)}";
            var sessionPath = Path.Combine(sessionDir, sessionName);

            // Build one command for the cracking run and a second --show pass so
            // the caller can display the recovered credentials immediately.
            var arguments = $"-m {hashcatMode} {Quote(hashFilePath)} {Quote(wordlistPath)} " +
                $"--outfile {Quote(outputFilePath)} " +
                $"--potfile-path {Quote(sessionDir)}\\ " +
                $"--session {Quote(sessionPath)}";

            if (!string.IsNullOrWhiteSpace(extraArguments))
            {
                arguments += " " + extraArguments;
            }

            var crackResult = RunProcess(hashcatExecutable, arguments);
            // --show doesn't need OpenCL, run from a writable temp dir to avoid
            // Permission Denied errors when hashcat writes show.pid/show.outfiles
            var showResult = RunProcess(hashcatExecutable, $"-m {hashcatMode} --show {Quote(hashFilePath)} --potfile-path {Quote(sessionDir)}\\", sessionDir);

            return new HashcatRunResult
            {
                ExitCode = crackResult.exitCode,
                StandardOutput = crackResult.output,
                StandardError = crackResult.error,
                ShowOutput = showResult.output,
                HashFilePath = hashFilePath,
                OutputFilePath = outputFilePath,
                HashcatMode = hashcatMode
            };
        }

        private static (int exitCode, string output, string error) RunProcess(string fileName, string arguments, string workingDirectory = null)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            if (File.Exists(fileName))
            {
                // Use a writable working directory so hashcat doesn't get
                // "Permission denied" when writing pid/induct files.
                // The writable dir has copies of OpenCL/modules/rules.
                if (workingDirectory == null)
                {
                    workingDirectory = EnsureWritableWorkingDir(fileName);
                }
                startInfo.WorkingDirectory = workingDirectory;
            }

            using (var process = new Process())
            {
                var output = new StringBuilder();
                var error = new StringBuilder();

                process.StartInfo = startInfo;
                process.OutputDataReceived += (s, e) =>
                {
                    if (e.Data != null)
                    {
                        output.AppendLine(e.Data);
                    }
                };
                process.ErrorDataReceived += (s, e) =>
                {
                    if (e.Data != null)
                    {
                        error.AppendLine(e.Data);
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();

                return (process.ExitCode, output.ToString(), error.ToString());
            }
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static string FindExecutableOnPath(string executableName)
        {
            var path = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            var fileNames = Path.HasExtension(executableName)
                ? new[] { executableName }
                : new[] { executableName + ".exe", executableName };

            foreach (var directory in path.Split(Path.PathSeparator))
            {
                if (string.IsNullOrWhiteSpace(directory))
                {
                    continue;
                }

                foreach (var fileName in fileNames)
                {
                    var candidate = Path.Combine(directory.Trim(), fileName);

                    if (File.Exists(candidate))
                    {
                        return Path.GetFullPath(candidate);
                    }
                }
            }

            return null;
        }
    }
}
