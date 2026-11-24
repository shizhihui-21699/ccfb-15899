using System.Globalization;
using System.Text;
using System.Text.Json;
using DetentionVerify.Core;

namespace DetentionVerify.Desktop;

/// <summary>
/// 备查导出。上级督查要的是“能带走、能复核”的凭据，而不是只能在本机看的数据库。
/// 同时导出：当日/区间流水 CSV、审计链、链头哈希与校验结果，便于对方独立复算。
/// </summary>
public static class EvidenceExporter
{
    public static string ExportDay(SqliteStore store, DateOnly day, string outDir, string actor)
    {
        Directory.CreateDirectory(outDir);
        var from = new DateTimeOffset(day.ToDateTime(TimeOnly.MinValue), TimeZoneInfo.Local.GetUtcOffset(DateTime.Now));
        var to = from.AddDays(1);

        var sessions = new SessionService(store).Recent(100_000, from)
            .Where(s => s.StartedAt < to).ToList();

        var stamp = new StringBuilder();
        stamp.AppendLine("律师会见身份核验 — 备查导出");
        stamp.AppendLine($"导出时间：{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        stamp.AppendLine($"导出人：{actor}");
        stamp.AppendLine($"数据区间：{from:yyyy-MM-dd HH:mm} — {to:yyyy-MM-dd HH:mm}");
        stamp.AppendLine($"记录数：{sessions.Count}");

        var csvPath = Path.Combine(outDir, $"sessions-{day:yyyyMMdd}.csv");
        WriteCsv(csvPath, sessions);

        var audit = AuditLog.Read(store, 100_000);
        var auditPath = Path.Combine(outDir, $"audit-{day:yyyyMMdd}.jsonl");
        File.WriteAllLines(auditPath, audit.Select(a => JsonSerializer.Serialize(a, JsonDefaults.Options)));

        var integrity = AuditLog.Verify(store);
        stamp.AppendLine($"审计链完整性：{(integrity.Intact ? "完整" : "异常：" + integrity.Problem)}");
        stamp.AppendLine($"审计事件数：{integrity.Count}");
        stamp.AppendLine($"链头哈希：{integrity.HeadHash}");
        stamp.AppendLine();
        stamp.AppendLine("复核方法：按 audit.jsonl 的 seq 顺序，对每条用 SHA-256(prevHash + \n + 规范化JSON) 重算，");
        stamp.AppendLine("与记录中的 hash 比对，并核对 prevHash 是否等于上一条的 hash。");
        stamp.AppendLine();
        stamp.AppendLine($"流水文件 SHA-256：{PackageSignature.HashFile(csvPath)}");
        stamp.AppendLine($"审计文件 SHA-256：{PackageSignature.HashFile(auditPath)}");

        var readmePath = Path.Combine(outDir, $"README-{day:yyyyMMdd}.txt");
        File.WriteAllText(readmePath, stamp.ToString(), new UTF8Encoding(true));

        return outDir;
    }

    private static void WriteCsv(string path, IReadOnlyList<SessionRecord> sessions)
    {
        var sb = new StringBuilder();
        sb.AppendLine("时间,律师,执业证号,律所,被会见人,结论,委托手续,人证对照,授权时间,授权码,复核人,放行理由,入所核销,撤销,民警,窗口,名册快照");
        foreach (var s in sessions)
        {
            sb.AppendLine(string.Join(',', new[]
            {
                Csv(s.StartedAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
                Csv(s.LawyerName), Csv(s.CertNo), Csv(s.FirmName),
                Csv(s.DetaineeName ?? s.DetaineeNo),
                Csv(OutcomeText(s.Outcome)),
                Csv(CommissionText(s.Commission)),
                Csv(PhotoVerdictText(s.PhotoVerdict)),
                Csv(s.AuthorizedAt?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
                Csv(s.AuthorizationCode), Csv(s.ReviewOfficer), Csv(s.CautionReason),
                Csv(s.CheckedInAt?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)),
                Csv(s.Revoked ? "已撤销：" + s.RevokedReason : ""),
                Csv(s.Officer), Csv(s.Window), Csv(s.SnapshotId),
            }));
        }
        File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
    }

    /// <summary>CSV 注入防护：以 = + - @ 开头的单元格加前置单引号，Excel 不会当公式执行。</summary>
    private static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var v = value;
        if (v[0] is '=' or '+' or '-' or '@' or '\t' or '\r') v = "'" + v;
        if (v.Contains('"') || v.Contains(',') || v.Contains('\n') || v.Contains('\r'))
            v = "\"" + v.Replace("\"", "\"\"") + "\"";
        return v;
    }

    public static string OutcomeText(string outcome) => outcome switch
    {
        "Verified" => "核验通过",
        "VerifiedWithCaution" => "有疑点放行",
        "NeedsManualReview" => "人工复核",
        _ => "禁止会见",
    };

    public static string CommissionText(CommissionKind kind) => kind switch
    {
        CommissionKind.Entrustment => "委托书",
        CommissionKind.LegalAid => "法律援助公函",
        CommissionKind.OfficialLetter => "单位介绍信",
        _ => "无",
    };

    public static string PhotoVerdictText(string verdict) => verdict switch
    {
        "Match" => "相符",
        "Doubtful" => "存疑",
        "Mismatch" => "不符",
        _ => "未比对",
    };
}
