using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace DetentionVerify.Core;

public static class RosterRepository
{
    public static RosterStampMeta? GetActiveStamp(SqliteStore store)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT snapshot_id,generated_at,imported_at,sequence,record_count
            FROM roster_snapshot WHERE is_active=1 LIMIT 1
            """;
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new RosterStampMeta(r.GetString(0),
            DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture),
            DateTimeOffset.Parse(r.GetString(2), CultureInfo.InvariantCulture),
            r.GetInt64(3), r.GetInt32(4));
    }

    public static RosterStamp GetStamp(SqliteStore store, RosterPolicy policy, DateTimeOffset now) =>
        GetActiveStamp(store) is { } meta ? policy.Evaluate(meta, now) : RosterStamp.Empty;

    public static LawyerLookup? Find(SqliteStore store, string certNo)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT cert_no,name,firm_name,firm_code,license_status,valid_from,valid_to,photo_sha256,
                   id_last6,practice_type,region,updated_at
            FROM lawyer WHERE cert_no=$c
            """;
        cmd.Parameters.AddWithValue("$c", certNo);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new LawyerLookup(
            r.GetString(0), r.GetString(1),
            r.IsDBNull(2) ? null : r.GetString(2),
            r.IsDBNull(3) ? null : r.GetString(3),
            (LicenseStatus)r.GetInt32(4),
            r.IsDBNull(5) ? null : DateOnly.ParseExact(r.GetString(5), "yyyy-MM-dd", CultureInfo.InvariantCulture),
            r.IsDBNull(6) ? null : DateOnly.ParseExact(r.GetString(6), "yyyy-MM-dd", CultureInfo.InvariantCulture),
            r.IsDBNull(7) ? null : r.GetString(7),
            r.IsDBNull(8) ? null : r.GetString(8),
            r.IsDBNull(9) ? null : r.GetString(9),
            r.IsDBNull(10) ? null : r.GetString(10),
            r.IsDBNull(11) ? null : DateTimeOffset.Parse(r.GetString(11), CultureInfo.InvariantCulture));
    }

    /// <summary>返回证号的近似候选，用于“输错一位”的提示。只返回已确认存在的记录，绝不作为通过依据。</summary>
    public static IReadOnlyList<string> NearMiss(SqliteStore store, string certNo, int max = 3)
    {
        if (certNo.Length is < 12 or > 24) return [];
        var prefix = certNo.Length >= 10 ? certNo[..8] : certNo;
        var suffix = certNo.Length >= 8 ? certNo[^6..] : certNo;

        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT cert_no FROM lawyer
            WHERE (cert_no LIKE $p || '%' OR cert_no LIKE '%' || $s)
            LIMIT 200
            """;
        cmd.Parameters.AddWithValue("$p", prefix);
        cmd.Parameters.AddWithValue("$s", suffix);
        using var r = cmd.ExecuteReader();
        var hits = new List<(string Cert, int Dist)>();
        while (r.Read())
        {
            var cert = r.GetString(0);
            var d = LicenseNumber.Distance(certNo, cert, 3);
            if (d is > 0 and <= 3) hits.Add((cert, d));
        }
        return hits.OrderBy(h => h.Dist).ThenBy(h => h.Cert).Select(h => h.Cert).Take(max).ToList();
    }

    public static bool ExistsByNameAndFirm(SqliteStore store, string name, string? firmName)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = firmName is null
            ? "SELECT 1 FROM lawyer WHERE name=$n LIMIT 1"
            : "SELECT 1 FROM lawyer WHERE name=$n AND firm_name=$f LIMIT 1";
        cmd.Parameters.AddWithValue("$n", name);
        if (firmName is not null) cmd.Parameters.AddWithValue("$f", firmName);
        return cmd.ExecuteScalar() is not null;
    }

    public static IReadOnlyList<(string CertNo, string Name, string? Firm)> Search(SqliteStore store, string query, int max = 20)
    {
        var q = LicenseNumber.NormalizeName(query);
        if (q.Length == 0) return [];
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        var digits = LicenseNumber.Normalize(query);
        cmd.CommandText = """
            SELECT cert_no,name,firm_name FROM lawyer
            WHERE name LIKE '%' || $q || '%' OR cert_no LIKE '%' || $d || '%' OR firm_name LIKE '%' || $q || '%'
            ORDER BY name LIMIT $m
            """;
        cmd.Parameters.AddWithValue("$q", q);
        cmd.Parameters.AddWithValue("$d", digits);
        cmd.Parameters.AddWithValue("$m", max);
        using var r = cmd.ExecuteReader();
        var list = new List<(string, string, string?)>();
        while (r.Read()) list.Add((r.GetString(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2)));
        return list;
    }

    /// <summary>
    /// 按编号精确查在押人员。刻意不提供按姓名查：同姓同名会让系统认错人，
    /// 而“认错会见对象”比“查不到”严重得多。
    /// </summary>
    public static DetaineeRecord? FindDetainee(SqliteStore store, string? detaineeNo)
    {
        if (string.IsNullOrWhiteSpace(detaineeNo)) return null;
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT detainee_no,name,room,status,restricted_reason FROM detainee WHERE detainee_no=$n";
        cmd.Parameters.AddWithValue("$n", detaineeNo.Trim());
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new DetaineeRecord
        {
            DetaineeNo = r.GetString(0),
            Name = r.GetString(1),
            Room = r.IsDBNull(2) ? null : r.GetString(2),
            Status = r.GetString(3),
            RestrictedReason = r.IsDBNull(4) ? null : r.GetString(4),
        };
    }

    public static PhotoRef? GetPhoto(SqliteStore store, string? sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return null;
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT content_type,bytes FROM photo WHERE sha256=$s";
        cmd.Parameters.AddWithValue("$s", sha256.ToLowerInvariant());
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new PhotoRef(sha256, (byte[])r[1], r.GetString(0));
    }

    public static int CountSessionsForLawyerToday(SqliteStore store, string certNo, DateTimeOffset dayStart, DateTimeOffset dayEnd)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM session WHERE cert_no=$c AND started_at>=$a AND started_at<$b AND revoked=0";
        cmd.Parameters.AddWithValue("$c", certNo);
        cmd.Parameters.AddWithValue("$a", dayStart.ToString("O"));
        cmd.Parameters.AddWithValue("$b", dayEnd.ToString("O"));
        return Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
    }

    public static bool HasOpenAuthorizationForDetainee(SqliteStore store, string certNo, string detaineeNo,
        DateTimeOffset dayStart, DateTimeOffset dayEnd)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT COUNT(*) FROM session
            WHERE cert_no=$c AND detainee_no=$d AND authorized_at IS NOT NULL AND revoked=0
              AND started_at>=$a AND started_at<$b
            """;
        cmd.Parameters.AddWithValue("$c", certNo);
        cmd.Parameters.AddWithValue("$d", detaineeNo);
        cmd.Parameters.AddWithValue("$a", dayStart.ToString("O"));
        cmd.Parameters.AddWithValue("$b", dayEnd.ToString("O"));
        return Convert.ToInt32(cmd.ExecuteScalar(), CultureInfo.InvariantCulture) > 0;
    }
}

public sealed record LawyerLookup(
    string CertNo, string Name, string? FirmName, string? FirmCode, LicenseStatus Status,
    DateOnly? ValidFrom, DateOnly? ValidTo, string? PhotoSha256, string? IdLast6,
    string? PracticeType, string? Region, DateTimeOffset? UpdatedAt)
{
    public LawyerRecord ToRecord() => new()
    {
        CertNo = CertNo,
        Name = Name,
        FirmName = FirmName,
        FirmCode = FirmCode,
        LicenseStatus = Status,
        ValidFrom = ValidFrom,
        ValidTo = ValidTo,
        PhotoSha256 = PhotoSha256,
        PracticeType = PracticeType,
        Region = Region,
        UpdatedAt = UpdatedAt,
    };
}
