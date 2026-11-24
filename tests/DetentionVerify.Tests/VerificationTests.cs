using DetentionVerify.Core;

namespace DetentionVerify.Tests;

public sealed class VerificationTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 9, 30, 0, TimeSpan.FromHours(8));
    private const string Cert = "11101202010123456";
    private const string Id = "110101199001011237";

    private readonly TestDb _db = new();
    private readonly PackageBuilder _pkg = new();

    public VerificationTests()
    {
        TrustedKeyRepository.Add(_db.Store, _pkg.TrustedKey(), "admin", Now);
        _pkg.GeneratedAt = Now.AddHours(-2);
        _pkg.AddDetainee("D-001", "李四");
    }

    private void Import(Action<PackageBuilder>? shape = null)
    {
        shape?.Invoke(_pkg);
        var dir = _pkg.Build();
        var r = new RosterImporter(_db.Store).Import(new ImportOptions(dir, "admin", Now));
        Assert.True(r.Ok, r.Message);
    }

    private VerificationDecision Run(string cert = Cert, string? name = "张伟", string? firm = null,
        string? id = null, string? detainee = "D-001", CommissionKind comm = CommissionKind.Entrustment,
        PhotoVerdict photo = PhotoVerdict.Match, DateTimeOffset? now = null)
        => new VerificationEngine(_db.Store).Evaluate(new VerificationRequest
        {
            CertNo = cert,
            Name = name,
            FirmName = firm,
            IdNumber = id,
            DetaineeNo = detainee,
            Commission = comm,
            PhotoVerdict = photo,
            Officer = "民警甲",
            Window = "1号窗口",
            Now = now ?? Now,
        });

    [Fact]
    public void ValidLawyerIsVerified()
    {
        Import(p => p.AddLawyer(Cert, "张伟", id: Id));
        var d = Run(id: Id);
        Assert.Equal(VerificationOutcome.Verified, d.Outcome);
        Assert.True(d.CanIssueDirectly);
    }

    [Fact]
    public void UnknownCertIsBlockedWhenRosterFresh()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        var d = Run(cert: "11101202010999999");
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "CERT_NOT_IN_ROSTER");
    }

    /// <summary>最关键的一条：名册过期时查无此人不能判伪造，必须降级为人工复核。</summary>
    [Fact]
    public void UnknownCertWithStaleRosterDegradesToManualReview()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        var d = Run(cert: "11101202010999999", now: Now.AddDays(7));
        Assert.Equal(VerificationOutcome.NeedsManualReview, d.Outcome);
        var c = d.Checks.Single(x => x.Code == "CERT_NOT_IN_ROSTER");
        Assert.Equal(Severity.Fail, c.Severity);
        Assert.Contains("名册未更新", c.Detail);
    }

    [Fact]
    public void NameMismatchBlocksForImpersonation()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        var d = Run(name: "李鬼");
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "NAME_MISMATCH");
    }

    [Fact]
    public void IdNumberMismatchBlocks()
    {
        Import(p => p.AddLawyer(Cert, "张伟", id: Id));
        var d = Run(name: "张伟", id: "110101199002022341");
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "ID_MISMATCH");
    }

    [Theory]
    [InlineData(LicenseStatus.Revoked)]
    [InlineData(LicenseStatus.Suspended)]
    [InlineData(LicenseStatus.Expired)]
    public void NonActiveLicenseBlocks(LicenseStatus status)
    {
        Import(p => p.AddLawyer(Cert, "张伟", status: status));
        var d = Run();
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
    }

    [Fact]
    public void ExpiredValidityDateBlocksEvenWhenStatusActive()
    {
        Import(p => p.AddLawyer(Cert, "张伟", validTo: new DateOnly(2025, 12, 31)));
        var d = Run();
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "LICENSE_PAST_VALIDITY");
    }

    [Fact]
    public void MissingCommissionBlocks()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        var d = Run(comm: CommissionKind.None);
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "COMMISSION_MISSING");
    }

    [Fact]
    public void PhotoMismatchBlocksButUncheckedIsOnlyCaution()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        Assert.Equal(VerificationOutcome.Blocked, Run(photo: PhotoVerdict.Mismatch).Outcome);

        var uncheckedDecision = Run(photo: PhotoVerdict.NotPerformed);
        Assert.Equal(VerificationOutcome.VerifiedWithCaution, uncheckedDecision.Outcome);
        Assert.Contains(uncheckedDecision.Checks, c => c.Code == "PHOTO_NOT_CHECKED");
    }

    [Fact]
    public void DoubtfulPhotoNeedsManualReview()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        var d = Run(photo: PhotoVerdict.Doubtful);
        Assert.Equal(VerificationOutcome.NeedsManualReview, d.Outcome);
    }

    [Fact]
    public void DetaineeNotInCustodyBlocks()
    {
        Import(p => p.AddLawyer(Cert, "张伟").AddDetainee("D-002", "王五", status: "已出所"));
        var d = Run(detainee: "D-002");
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "DETAINEE_NOT_IN_CUSTODY");
    }

    [Fact]
    public void RestrictedDetaineeBlocks()
    {
        Import(p => p.AddLawyer(Cert, "张伟").AddDetainee("D-003", "赵六", restricted: "涉黑案件，禁止会见"));
        var d = Run(detainee: "D-003");
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "DETAINEE_RESTRICTED");
    }

    [Fact]
    public void NearMissSuggestsTypo()
    {
        Import(p => p.AddLawyer(Cert, "张伟"));
        var typo = Cert[..^1] + "7";
        var d = Run(cert: typo);
        Assert.Contains(Cert, d.NearMissCertNos);
    }

    [Fact]
    public void MissingRosterBlocksWithClearGuidance()
    {
        var d = new VerificationEngine(_db.Store).Evaluate(new VerificationRequest
        {
            CertNo = Cert, Name = "张伟", Officer = "民警甲", Window = "1号窗口", Now = Now,
        });
        Assert.Equal(VerificationOutcome.Blocked, d.Outcome);
        Assert.Contains(d.Checks, c => c.Code == "ROSTER_MISSING");
    }

    [Fact]
    public void FullWidthAndSeparatorsAreNormalized()
    {
        Import(p => p.AddLawyer(Cert, "张 伟"));
        var d = Run(cert: "１１１０１２０２０１０－１２３４５６", name: "张伟");
        Assert.True(d.Outcome == VerificationOutcome.Verified, string.Join("; ", d.Checks.Select(c => c.Title)));
    }

    public void Dispose()
    {
        _db.Dispose();
        _pkg.Dispose();
    }
}
