using DetentionVerify.Core;

namespace DetentionVerify.Tests;

public sealed class SessionAndAuditTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 9, 30, 0, TimeSpan.FromHours(8));
    private const string Cert = "11101202010123456";
    private const string Secret = "window-1-daily-secret";

    private readonly TestDb _db = new();
    private readonly PackageBuilder _pkg = new();

    public SessionAndAuditTests()
    {
        TrustedKeyRepository.Add(_db.Store, _pkg.TrustedKey(), "admin", Now);
        _pkg.GeneratedAt = Now.AddHours(-1);
        _pkg.AddLawyer(Cert, "张伟").AddDetainee("D-001", "李四");
        var r = new RosterImporter(_db.Store).Import(new ImportOptions(_pkg.Build(), "admin", Now));
        Assert.True(r.Ok, r.Message);
    }

    private VerificationDecision Decision(PhotoVerdict photo = PhotoVerdict.Match, string name = "张伟") =>
        new VerificationEngine(_db.Store).Evaluate(new VerificationRequest
        {
            CertNo = Cert, Name = name, DetaineeNo = "D-001", Commission = CommissionKind.Entrustment,
            PhotoVerdict = photo, Officer = "民警甲", Window = "1号窗口", Now = Now,
        });

    private SessionService Service() => new(_db.Store, _db.Clock);

    private SessionRecord Start(VerificationDecision d) =>
        Service().Start(new VerificationRequest
        {
            CertNo = Cert, Name = "张伟", DetaineeNo = "D-001", Commission = CommissionKind.Entrustment,
            PhotoVerdict = PhotoVerdict.Match, Officer = "民警甲", Window = "1号窗口", Now = Now,
        }, d, Guid.NewGuid().ToString("N"));

    [Fact]
    public void VerifiedCanAuthorizeDirectly()
    {
        var s = Start(Decision());
        var result = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, null, null,
            null, Secret, Now));
        Assert.True(result.Succeeded, result.Message);
        Assert.Matches("^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$", result.Code);
    }

    [Fact]
    public void BlockedCannotBeAuthorized()
    {
        var s = Start(Decision(name: "冒用者"));  // 姓名不符 → 禁止
        var result = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", "熟人放行", "所长", "同意放行",
            null, Secret, Now));
        Assert.False(result.Succeeded);
        Assert.Contains("禁止", result.Message);
    }

    [Fact]
    public void ManualReviewRequiresSecondOfficer()
    {
        var s = Start(Decision(photo: PhotoVerdict.Doubtful));  // → 需复核

        var selfReview = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, "民警甲", "本人核实无误",
            null, Secret, Now));
        Assert.False(selfReview.Succeeded);
        Assert.Contains("同一人", selfReview.Message);

        var ok = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, "值班长乙", "核对身份证原件一致",
            null, Secret, Now));
        Assert.True(ok.Succeeded, ok.Message);
    }

    [Fact]
    public void CautionRequiresWrittenReason()
    {
        var s = Start(Decision(photo: PhotoVerdict.NotPerformed));  // → 有疑点
        var noReason = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", " ", null, null, null, Secret, Now));
        Assert.False(noReason.Succeeded);

        var ok = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", "证件照为十年前，本人已核对身份证原件",
            null, null, null, Secret, Now));
        Assert.True(ok.Succeeded, ok.Message);
    }

    [Fact]
    public void AuthorizationCannotBeIssuedTwice()
    {
        var s = Start(Decision());
        Assert.True(Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, null, null, null, Secret, Now)).Succeeded);
        var again = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, null, null, null, Secret, Now));
        Assert.False(again.Succeeded);
    }

    [Fact]
    public void AuthorizationCodeIsBoundToSessionAndDay()
    {
        var s = Start(Decision());
        var code = Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, null, null, null, Secret, Now)).Code!;

        Assert.True(AuthorizationCode.Verify(code, s.SessionId, Cert, "D-001", Now, Secret));
        Assert.False(AuthorizationCode.Verify(code, s.SessionId, Cert, "D-002", Now, Secret));      // 换在押人员
        Assert.False(AuthorizationCode.Verify(code, "other-session", Cert, "D-001", Now, Secret));  // 换会话
        Assert.False(AuthorizationCode.Verify(code, s.SessionId, Cert, "D-001", Now.AddDays(1), Secret)); // 隔日
        Assert.False(AuthorizationCode.Verify(code, s.SessionId, Cert, "D-001", Now, "another-secret"));  // 换窗口密钥
    }

    [Fact]
    public void RevokeRequiresReasonAndIsAudited()
    {
        var s = Start(Decision());
        Assert.Throws<ArgumentException>(() => Service().Revoke(s.SessionId, "民警甲", "  ", Now));
        Service().Revoke(s.SessionId, "民警甲", "发现委托书系伪造", Now);
        var after = Service().Get(s.SessionId)!;
        Assert.True(after.Revoked);
        Assert.Contains(AuditLog.Read(_db.Store, 50), e => e.Category == "session.revoke");
    }

    [Fact]
    public void AuditChainIsIntactAfterNormalUse()
    {
        var s = Start(Decision());
        Service().Authorize(new AuthorizeRequest(s.SessionId, "民警甲", null, null, null, null, Secret, Now));
        var report = AuditLog.Verify(_db.Store);
        Assert.True(report.Intact, report.Problem);
        Assert.True(report.Count >= 3);
    }

    [Fact]
    public void AuditChainDetectsRecordDeletion()
    {
        for (var i = 0; i < 5; i++) Start(Decision());

        using (var conn = _db.Store.OpenConnection())
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM audit_event WHERE seq=3";
            cmd.ExecuteNonQuery();
        }

        var report = AuditLog.Verify(_db.Store);
        Assert.False(report.Intact);
        Assert.Contains("删除", report.Problem);
    }

    [Fact]
    public void AuditChainDetectsPayloadEdit()
    {
        for (var i = 0; i < 4; i++) Start(Decision());

        using (var conn = _db.Store.OpenConnection())
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE audit_event SET payload_json='{\"tampered\":true}' WHERE seq=2";
            cmd.ExecuteNonQuery();
        }

        var report = AuditLog.Verify(_db.Store);
        Assert.False(report.Intact);
        Assert.Equal(2, report.FirstProblemSeq);
    }

    [Fact]
    public void SameDayRepeatMeetingRaisesCaution()
    {
        var first = Start(Decision());
        Service().Authorize(new AuthorizeRequest(first.SessionId, "民警甲", null, null, null, null, Secret, Now));

        var second = new VerificationEngine(_db.Store).Evaluate(new VerificationRequest
        {
            CertNo = Cert, Name = "张伟", DetaineeNo = "D-001", Commission = CommissionKind.Entrustment,
            PhotoVerdict = PhotoVerdict.Match, Officer = "民警甲", Window = "1号窗口", Now = Now.AddHours(2),
        });

        Assert.Contains(second.Checks, c => c.Code == "SAME_DAY_REPEAT");
        Assert.Equal(VerificationOutcome.VerifiedWithCaution, second.Outcome);
    }

    public void Dispose()
    {
        _db.Dispose();
        _pkg.Dispose();
    }
}
