// Code updates by Ayman Elbanhawy (c) Softwaremile.com
// SQLite-based case management for BruteShark Studio.
// Provides persistent storage for analysis results with:
//  - Multi-PCAP case organization
//  - Full-text search across extracted data
//  - Timeline reconstruction
//  - Query capabilities (show all hosts that contacted IP X across all analyses)

using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;

namespace CommonUi
{
    /// <summary>
    /// Manages analysis cases in a SQLite database with tables for
    /// passwords, hashes, files, DNS mappings, connections, sessions,
    /// JA3 fingerprints, beacon detections, and rule matches.
    /// </summary>
    public class CaseManager : IDisposable
    {
        private readonly SqliteConnection _db;
        private readonly string _dbPath;
        private bool _disposed;

        public string CaseName { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public string DatabasePath => _dbPath;

        public CaseManager(string dbPath = null)
        {
            _dbPath = dbPath ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "BruteSharkStudio",
                "cases.db");

            Directory.CreateDirectory(Path.GetDirectoryName(_dbPath));

            _db = new SqliteConnection($"Data Source={_dbPath}");
            _db.Open();
            InitializeSchema();
        }

        private void InitializeSchema()
        {
            using var cmd = _db.CreateCommand();

            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    status TEXT DEFAULT 'open',
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS case_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    status TEXT DEFAULT 'pending',
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    protocol TEXT,
                    username TEXT,
                    password TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    hash_type TEXT,
                    hash_value TEXT NOT NULL,
                    username TEXT,
                    domain TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    hashcat_mode INTEGER,
                    cracked_password TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS extracted_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    file_name TEXT,
                    extension TEXT,
                    size INTEGER,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    sha256 TEXT,
                    file_path TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS dns_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    query TEXT NOT NULL,
                    destination TEXT,
                    source_ip TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    packet_count INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS ja3_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    ja3_hash TEXT NOT NULL,
                    ja3_string TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    known_software TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS beacon_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    pair_key TEXT,
                    c2_server TEXT,
                    connection_count INTEGER,
                    mean_interval_seconds REAL,
                    jitter_ratio REAL,
                    size_similarity REAL,
                    beacon_score REAL,
                    destination_port INTEGER,
                    observation_hours REAL,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS detection_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    category TEXT,
                    severity TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    mitre_technique TEXT,
                    match_details TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                -- Indexes for fast querying
                CREATE INDEX IF NOT EXISTS idx_passwords_case ON passwords(case_id);
                CREATE INDEX IF NOT EXISTS idx_hashes_case ON hashes(case_id);
                CREATE INDEX IF NOT EXISTS idx_connections_src ON network_connections(source_ip);
                CREATE INDEX IF NOT EXISTS idx_connections_dst ON network_connections(destination_ip);
                CREATE INDEX IF NOT EXISTS idx_dns_query ON dns_mappings(query);
                CREATE INDEX IF NOT EXISTS idx_ja3_hash ON ja3_fingerprints(ja3_hash);
                CREATE INDEX IF NOT EXISTS idx_beacon_score ON beacon_detections(beacon_score DESC);
            ";
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Create a new analysis case.
        /// </summary>
        public long CreateCase(string name, string notes = null)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "INSERT INTO cases (name, notes, created_at) VALUES (@name, @notes, @ts)";
            cmd.Parameters.AddWithValue("@name", name);
            cmd.Parameters.AddWithValue("@notes", (object)notes ?? DBNull.Value);
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));

            cmd.ExecuteNonQuery();

            cmd.CommandText = "SELECT last_insert_rowid()";
            var caseId = (long)cmd.ExecuteScalar();

            CaseName = name;
            CreatedAt = DateTime.UtcNow;

            return caseId;
        }

        /// <summary>
        /// Store extracted credentials in the case database.
        /// </summary>
        public void StorePassword(long caseId, PcapAnalyzer.NetworkPassword pw)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = @"INSERT INTO passwords 
                (case_id, protocol, username, password, source_ip, destination_ip, source_port, destination_port, timestamp)
                VALUES (@cid, @proto, @user, @pwd, @src, @dst, @sp, @dp, @ts)";
            cmd.Parameters.AddWithValue("@cid", caseId);
            cmd.Parameters.AddWithValue("@proto", pw.Protocol ?? "");
            cmd.Parameters.AddWithValue("@user", pw.Username ?? "");
            cmd.Parameters.AddWithValue("@pwd", pw.Password ?? "");
            cmd.Parameters.AddWithValue("@src", pw.Source ?? "");
            cmd.Parameters.AddWithValue("@dst", pw.Destination ?? "");
            cmd.Parameters.AddWithValue("@sp", 0);
            cmd.Parameters.AddWithValue("@dp", 0);
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Store extracted hash in the case database.
        /// </summary>
        public void StoreHash(long caseId, PcapAnalyzer.NetworkHash hash)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = @"INSERT INTO hashes 
                (case_id, hash_type, hash_value, username, domain, source_ip, destination_ip, protocol, hashcat_mode, timestamp)
                VALUES (@cid, @ht, @hv, @user, @dom, @src, @dst, @proto, @mode, @ts)";

            int hashcatMode = 0;
            // Map known hash types to their Hashcat mode numbers
            if (hash is PcapAnalyzer.NtlmHash n && n.NtHash?.Length > 24) hashcatMode = 5600;
            else if (hash is PcapAnalyzer.NtlmHash n2 && n2.NtHash?.Length == 24) hashcatMode = 5500;
            else if (hash is PcapAnalyzer.KerberosHash) hashcatMode = 7500;
            else if (hash is PcapAnalyzer.KerberosAsRepHash) hashcatMode = 18200;
            else if (hash is PcapAnalyzer.KerberosTgsRepHash k3 && k3.Etype == 23) hashcatMode = 13100;
            else if (hash is PcapAnalyzer.KerberosTgsRepHash k4 && k4.Etype == 17) hashcatMode = 19600;
            else if (hash is PcapAnalyzer.KerberosTgsRepHash k5 && k5.Etype == 18) hashcatMode = 19700;
            else if (hash is PcapAnalyzer.HttpDigestHash) hashcatMode = 11400;
            else if (hash is PcapAnalyzer.CramMd5Hash) hashcatMode = 16400;

            cmd.Parameters.AddWithValue("@cid", caseId);
            cmd.Parameters.AddWithValue("@ht", hash.HashType ?? "");
            cmd.Parameters.AddWithValue("@hv", hash.Hash ?? "");
            cmd.Parameters.AddWithValue("@user", (hash is PcapAnalyzer.IDomainCredential dc) ? dc.GetUsername() : "");
            cmd.Parameters.AddWithValue("@dom", (hash is PcapAnalyzer.IDomainCredential dc2) ? dc2.GetDoamin() : "");
            cmd.Parameters.AddWithValue("@src", hash.Source ?? "");
            cmd.Parameters.AddWithValue("@dst", hash.Destination ?? "");
            cmd.Parameters.AddWithValue("@proto", hash.Protocol ?? "");
            cmd.Parameters.AddWithValue("@mode", hashcatMode);
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Store JA3 fingerprint.
        /// </summary>
        public void StoreJa3Fingerprint(long caseId, PcapAnalyzer.Ja3Fingerprint ja3)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = @"INSERT INTO ja3_fingerprints
                (case_id, ja3_hash, ja3_string, source_ip, destination_ip, destination_port, known_software, timestamp)
                VALUES (@cid, @hash, @str, @src, @dst, @dp, @sw, @ts)";
            cmd.Parameters.AddWithValue("@cid", caseId);
            cmd.Parameters.AddWithValue("@hash", ja3.Ja3Hash);
            cmd.Parameters.AddWithValue("@str", ja3.Ja3String ?? "");
            cmd.Parameters.AddWithValue("@src", ja3.SourceIp ?? "");
            cmd.Parameters.AddWithValue("@dst", ja3.DestinationIp ?? "");
            cmd.Parameters.AddWithValue("@dp", ja3.DestinationPort);
            cmd.Parameters.AddWithValue("@sw", ja3.KnownSoftware ?? "");
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Store beacon detection result.
        /// </summary>
        public void StoreBeaconResult(long caseId, PcapAnalyzer.BeaconResult beacon)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = @"INSERT INTO beacon_detections
                (case_id, pair_key, c2_server, connection_count, mean_interval_seconds,
                 jitter_ratio, size_similarity, beacon_score, destination_port, observation_hours, timestamp)
                VALUES (@cid, @pk, @c2, @cc, @mi, @jr, @ss, @bs, @dp, @oh, @ts)";
            cmd.Parameters.AddWithValue("@cid", caseId);
            cmd.Parameters.AddWithValue("@pk", beacon.PairKey ?? "");
            cmd.Parameters.AddWithValue("@c2", beacon.ProbableC2Server ?? "");
            cmd.Parameters.AddWithValue("@cc", beacon.ConnectionCount);
            cmd.Parameters.AddWithValue("@mi", beacon.MeanIntervalSeconds);
            cmd.Parameters.AddWithValue("@jr", beacon.JitterRatio);
            cmd.Parameters.AddWithValue("@ss", beacon.SizeSimilarity);
            cmd.Parameters.AddWithValue("@bs", beacon.BeaconScore);
            cmd.Parameters.AddWithValue("@dp", beacon.DestinationPort);
            cmd.Parameters.AddWithValue("@oh", beacon.ObservationPeriod.TotalHours);
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Store detection rule match.
        /// </summary>
        public void StoreDetectionMatch(long caseId, PcapAnalyzer.RuleMatch match)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = @"INSERT INTO detection_matches
                (case_id, rule_name, category, severity, source_ip, destination_ip, mitre_technique, match_details, timestamp)
                VALUES (@cid, @rn, @cat, @sev, @src, @dst, @mt, @md, @ts)";
            cmd.Parameters.AddWithValue("@cid", caseId);
            cmd.Parameters.AddWithValue("@rn", match.RuleName ?? "");
            cmd.Parameters.AddWithValue("@cat", match.Category ?? "");
            cmd.Parameters.AddWithValue("@sev", match.Severity ?? "");
            cmd.Parameters.AddWithValue("@src", match.SourceIp ?? "");
            cmd.Parameters.AddWithValue("@dst", match.DestinationIp ?? "");
            cmd.Parameters.AddWithValue("@mt", match.MitreTechnique ?? "");
            cmd.Parameters.AddWithValue("@md", match.MatchDetails ?? "");
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
            cmd.ExecuteNonQuery();
        }

        /// <summary>
        /// Query all hosts that communicated with a given IP across all cases.
        /// </summary>
        public List<(string peerIp, int port, string protocol)> GetPeersForIp(string ipAddress)
        {
            var results = new List<(string, int, string)>();
            using var cmd = _db.CreateCommand();
            cmd.CommandText = @"
                SELECT DISTINCT destination_ip, destination_port, protocol FROM network_connections WHERE source_ip = @ip
                UNION
                SELECT DISTINCT source_ip, source_port, protocol FROM network_connections WHERE destination_ip = @ip";
            cmd.Parameters.AddWithValue("@ip", ipAddress);

            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add((
                    reader.GetString(0),
                    reader.GetInt32(1),
                    reader.GetString(2)));
            }
            return results;
        }

        /// <summary>
        /// Search across all extracted data for a text pattern.
        /// </summary>
        public List<Dictionary<string, object>> SearchAll(string query)
        {
            var results = new List<Dictionary<string, object>>();
            var searchParam = $"%{query}%";

            // Search passwords
            using (var cmd = _db.CreateCommand())
            {
                cmd.CommandText = @"SELECT 'Password' as type, protocol, username, password, source_ip, destination_ip 
                    FROM passwords WHERE username LIKE @q OR password LIKE @q OR protocol LIKE @q LIMIT 50";
                cmd.Parameters.AddWithValue("@q", searchParam);
                using var r = cmd.ExecuteReader();
                while (r.Read())
                    results.Add(new Dictionary<string, object> {
                        ["Type"] = "Password", ["Protocol"] = r.GetString(1),
                        ["User"] = r.GetString(2), ["Details"] = $"{r.GetString(2)} -> {r.GetString(5)}"
                    });
            }

            // Search hashes
            using (var cmd = _db.CreateCommand())
            {
                cmd.CommandText = @"SELECT 'Hash' as type, hash_type, hash_value, username, domain, source_ip
                    FROM hashes WHERE username LIKE @q OR domain LIKE @q OR hash_type LIKE @q LIMIT 50";
                cmd.Parameters.AddWithValue("@q", searchParam);
                using var r = cmd.ExecuteReader();
                while (r.Read())
                    results.Add(new Dictionary<string, object> {
                        ["Type"] = "Hash", ["HashType"] = r.GetString(1),
                        ["User"] = r.GetString(3), ["Domain"] = r.GetString(4)
                    });
            }

            return results;
        }

        /// <summary>
        /// Get case summary for reporting.
        /// </summary>
        public Dictionary<string, object> GetCaseSummary(long caseId)
        {
            var summary = new Dictionary<string, object>();

            using var cmd = _db.CreateCommand();
            cmd.Parameters.AddWithValue("@cid", caseId);

            // Count by table
            var tables = new[] { "passwords", "hashes", "extracted_files", "dns_mappings",
                "network_connections", "ja3_fingerprints", "beacon_detections", "detection_matches" };

            foreach (var table in tables)
            {
                cmd.CommandText = $"SELECT COUNT(*) FROM {table} WHERE case_id = @cid";
                var count = (long)cmd.ExecuteScalar();
                summary[table] = count;
            }

            // High-severity findings
            cmd.CommandText = "SELECT COUNT(*) FROM detection_matches WHERE case_id = @cid AND severity IN ('High','Critical')";
            summary["high_severity_matches"] = (long)cmd.ExecuteScalar();

            // Unique hosts
            cmd.CommandText = @"SELECT COUNT(DISTINCT source_ip) FROM network_connections WHERE case_id = @cid";
            summary["unique_sources"] = (long)cmd.ExecuteScalar();

            return summary;
        }

        /// <summary>
        /// Close case and mark as completed.
        /// </summary>
        public void CloseCase(long caseId)
        {
            using var cmd = _db.CreateCommand();
            cmd.CommandText = "UPDATE cases SET status = 'closed' WHERE id = @id";
            cmd.Parameters.AddWithValue("@id", caseId);
            cmd.ExecuteNonQuery();
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _db?.Close();
                _db?.Dispose();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }
    }
}
