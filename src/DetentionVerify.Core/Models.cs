namespace DetentionVerify.Core;

/// <summary>律师执业证状态。吊销/注销/停业期间一律不得会见。</summary>
public enum LicenseStatus
{
    Unknown = 0,
    Active = 1,
    Suspended = 2,
    Revoked = 3,
    Expired = 4,
}

/// <summary>委托手续类型。窗口必须收到其中一种纸质/电子手续才能授权会见。</summary>
public enum CommissionKind
{
    None = 0,
    Entrustment = 1,   // 委托书
    LegalAid = 2,      // 法律援助公函
    OfficialLetter = 3, // 单位介绍信
}

/// <summary>人证比对结论，由窗口民警肉眼比对后录入，系统不做自动人脸判定。</summary>
public enum PhotoVerdict
{
    NotPerformed = 0,
    Match = 1,
    Doubtful = 2,
    Mismatch = 3,
}

public enum Severity
{
    Info = 0,
    Caution = 1,
    Fail = 2,
    Block = 3,
}

public enum VerificationOutcome
{
    Verified = 0,             // 全部通过
    VerifiedWithCaution = 1,  // 有疑点但可会见，需写明事由
    NeedsManualReview = 2,    // 系统无法判定，须值班长/人工核实
    Blocked = 3,              // 命中禁止条件，原则上不得会见
}

/// <summary>外部系统导入的律师档案。仅在导入包内出现明文身份证号，落库前即被哈希。</summary>
public sealed record LawyerRecord
{
    public required string CertNo { get; init; }
    public required string Name { get; init; }
    public string? FirmName { get; init; }
    public string? FirmCode { get; init; }
    public LicenseStatus LicenseStatus { get; init; } = LicenseStatus.Unknown;
    public DateOnly? ValidFrom { get; init; }
    public DateOnly? ValidTo { get; init; }
    /// <summary>身份证号，仅存在于签名包内，绝不落库。</summary>
    public string? IdNumber { get; init; }
    public string? PhotoSha256 { get; init; }
    public string? PracticeType { get; init; }
    public string? Region { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}

public sealed record DetaineeRecord
{
    public required string DetaineeNo { get; init; }
    public required string Name { get; init; }
    public string? Room { get; init; }
    /// <summary>在押 / 出所 / 转监 / 释放。</summary>
    public string Status { get; init; } = "在押";
    public string? RestrictedReason { get; init; }
}

/// <summary>
/// 会见预约。高峰时窗口可凭此名单点名核验，避免律师在窗口口述/手写证号造成的排队与录入错误。
/// 预约不等于授权：仍必须完成身份核验与手续检查。
/// </summary>
public sealed record AppointmentRecord
{
    public required string AppointmentId { get; init; }
    /// <summary>预约日期（本地日期）。</summary>
    public required DateOnly Date { get; init; }
    /// <summary>时段，如 "09:00-09:30"。用于窗口排序，不用于强制限制。</summary>
    public string? Slot { get; init; }
    public required string CertNo { get; init; }
    public string? LawyerName { get; init; }
    public string? DetaineeNo { get; init; }
    public string? DetaineeName { get; init; }
    public CommissionKind Commission { get; init; }
    public string? CommissionNo { get; init; }
    /// <summary>预约状态：已确认 / 待确认 / 已取消。</summary>
    public string Status { get; init; } = "已确认";
}

/// <summary>导入包清单。签名覆盖 manifest.json 原始字节，manifest 再覆盖 records/detainees/photos。</summary>
public sealed record RosterManifest
{
    public string Format { get; init; } = "detention-roster/v1";
    public required string SnapshotId { get; init; }
    public required DateTimeOffset GeneratedAt { get; init; }
    public string? SourceSystem { get; init; }
    public long Sequence { get; init; }
    public required string KeyId { get; init; }
    public int RecordCount { get; init; }
    public int DetaineeCount { get; init; }
    public required string RecordsSha256 { get; init; }
    public required string DetaineesSha256 { get; init; }
    /// <summary>可选的预约名单哈希。为空表示本包不含预约数据，不影响身份核验。</summary>
    public string? AppointmentsSha256 { get; init; }
    public string? PrevSnapshotId { get; init; }
}

/// <summary>当前生效名册的元信息，用于核验时标注数据时效。</summary>
public sealed record RosterStamp(
    string SnapshotId,
    DateTimeOffset GeneratedAt,
    DateTimeOffset ImportedAt,
    TimeSpan Age,
    bool IsStale,
    bool IsDegraded,
    long Sequence,
    int RecordCount)
{
    public static RosterStamp Empty { get; } = new("", DateTimeOffset.MinValue, DateTimeOffset.MinValue,
        TimeSpan.MaxValue, true, true, 0, 0);

    public bool Exists => !string.IsNullOrEmpty(SnapshotId);
}

/// <summary>名册时效策略。内网只能定期导入，陈旧是常态，必须区分“没这个人”和“数据还没到”。</summary>
public sealed record RosterPolicy(TimeSpan WarnAfter, TimeSpan DegradeAfter)
{
    public static RosterPolicy Default { get; } = new(TimeSpan.FromHours(30), TimeSpan.FromHours(96));

    public RosterStamp Evaluate(RosterStampMeta meta, DateTimeOffset now)
    {
        var age = now - meta.GeneratedAt;
        return new RosterStamp(meta.SnapshotId, meta.GeneratedAt, meta.ImportedAt, age,
            age >= WarnAfter, age >= DegradeAfter, meta.Sequence, meta.RecordCount);
    }
}

public readonly record struct RosterStampMeta(
    string SnapshotId, DateTimeOffset GeneratedAt, DateTimeOffset ImportedAt, long Sequence, int RecordCount);

public sealed record CheckResult(string Code, Severity Severity, string Title, string? Detail = null)
{
    public bool Blocks => Severity == Severity.Block;
}

public sealed record PhotoRef(string Sha256, byte[] Bytes, string ContentType)
{
    public string DataUri() => $"data:{ContentType};base64,{Convert.ToBase64String(Bytes)}";
}

public sealed record VerificationRequest
{
    public required string CertNo { get; init; }
    public string? Name { get; init; }
    public string? FirmName { get; init; }
    public string? IdNumber { get; init; }
    public string? IdLast6 { get; init; }
    public string? DetaineeNo { get; init; }
    public CommissionKind Commission { get; init; }
    public string? CommissionNo { get; init; }
    public PhotoVerdict PhotoVerdict { get; init; }
    public string? Notes { get; init; }
    public required string Officer { get; init; }
    public required string Window { get; init; }
    public required DateTimeOffset Now { get; init; }
}

public sealed record VerificationDecision
{
    public required VerificationOutcome Outcome { get; init; }
    public required IReadOnlyList<CheckResult> Checks { get; init; }
    public LawyerRecord? Lawyer { get; init; }
    public DetaineeRecord? Detainee { get; init; }
    public PhotoRef? Photo { get; init; }
    public required RosterStamp Roster { get; init; }
    /// <summary>与输入相近但不同的证号，用于提示窗口人员输错。</summary>
    public IReadOnlyList<string> NearMissCertNos { get; init; } = [];
    public bool CanIssueDirectly => Outcome is VerificationOutcome.Verified;
    public bool RequiresCautionReason => Outcome is VerificationOutcome.VerifiedWithCaution;
    public bool RequiresSupervisor => Outcome is VerificationOutcome.NeedsManualReview or VerificationOutcome.Blocked;
    public string Headline => Outcome switch
    {
        VerificationOutcome.Verified => "核验通过",
        VerificationOutcome.VerifiedWithCaution => "可以会见（有疑点，需注明）",
        VerificationOutcome.NeedsManualReview => "须人工复核",
        _ => "禁止会见",
    };
}

public sealed record SessionRecord
{
    public required string SessionId { get; init; }
    public required string CertNo { get; init; }
    public string? LawyerName { get; init; }
    public string? FirmName { get; init; }
    public required string SnapshotId { get; init; }
    public required string Outcome { get; init; }
    public required string Officer { get; init; }
    public required string Window { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset? AuthorizedAt { get; init; }
    public string? AuthorizationCode { get; init; }
    public string? DetaineeNo { get; init; }
    public string? DetaineeName { get; init; }
    public CommissionKind Commission { get; init; }
    public string? CommissionNo { get; init; }
    public string PhotoVerdict { get; init; } = "NotPerformed";
    public string? CautionReason { get; init; }
    public string? ReviewOfficer { get; init; }
    public string? ReviewNote { get; init; }
    public string? ChecksJson { get; init; }
    public DateTimeOffset? CheckedInAt { get; init; }
    public string? CheckedInBy { get; init; }
    public string? PhotoSha256 { get; init; }
    public bool Revoked { get; init; }
    public string? RevokedReason { get; init; }
}

public sealed record AuditEvent(long Seq, DateTimeOffset OccurredAt, string Category, string Actor,
    string Subject, string PayloadJson, string PrevHash, string Hash);

public sealed record TrustedKey(string KeyId, string Algorithm, string PublicKeyBase64, string? Label,
    DateTimeOffset? NotBefore = null, DateTimeOffset? NotAfter = null);
