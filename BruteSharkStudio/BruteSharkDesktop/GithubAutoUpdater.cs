using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;

namespace BruteSharkDesktop
{
    // Code updates by Ayman Elbanhawy (c) Softwaremile.com
    // The updater checks the GitHub releases page for this maintained fork and
    // compares release tags against the desktop assembly file version.
    public struct GithubReleaseVersion
    {
        public string Version { get; set; }
        public string LatestVersionUrl { get; set; }
    }

    public struct GithubUpdateReleaseResponse
    {
        public bool ShouldUpdate { get; set; }
        public string NewVersionUrl { get; set; }
    }

    public static class GithubAutoUpdater
    {
        public static string GetAssemblyVersion()
        {
            System.Reflection.Assembly executingAssembly = System.Reflection.Assembly.GetExecutingAssembly();
            var fieVersionInfo = FileVersionInfo.GetVersionInfo(executingAssembly.Location);
            return fieVersionInfo.FileVersion;
        }

        public static async Task<GithubReleaseVersion> GetRemoteVersion(string ownerName, string projectName)
        {
            var client = new Octokit.GitHubClient(new Octokit.ProductHeaderValue("my-cool-app"));
            var releases = await client.Repository.Release.GetAll(owner: ownerName, name: projectName);
            var latest = releases[0];

            return new GithubReleaseVersion()
            {
                Version = latest.TagName,
                LatestVersionUrl = latest.HtmlUrl
            };
        }

        public static async Task<GithubUpdateReleaseResponse> ShouldUpdate(string ownerName, string projectName)
        {
            // Get current running assembly version and the latest release from GitHub.
            Task<GithubReleaseVersion> getRemoteVersion = GithubAutoUpdater.GetRemoteVersion(ownerName, projectName);
            string currentVersionName = GithubAutoUpdater.GetAssemblyVersion();
            GithubReleaseVersion remoteVersionDetails = await getRemoteVersion;
            string remoteVersionName = remoteVersionDetails.Version;

            // Release tags may be published as v1.2.17 while the local file
            // version is stored as 1.2.17.0, so normalize the tag prefix first.
            char[] charsToRemove = { 'V', 'v' };
            var remoteVersion = new Version(remoteVersionName.TrimStart(charsToRemove));
            var currentVersion = new Version(currentVersionName.TrimStart(charsToRemove));

            var result = new GithubUpdateReleaseResponse();

            if (currentVersion < remoteVersion)
            {
                result.ShouldUpdate = true;
                result.NewVersionUrl = remoteVersionDetails.LatestVersionUrl;
            }
            else
            {
                result.ShouldUpdate = false;
                result.NewVersionUrl = string.Empty;
            }

            return result;
        }

    }
}
