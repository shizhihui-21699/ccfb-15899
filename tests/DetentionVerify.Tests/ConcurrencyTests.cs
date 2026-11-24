using DetentionVerify.Core;

namespace DetentionVerify.Tests;

/// <summary>
/// 高峰时多个窗口同时操作。单机 SQLite 的并发边界必须验证：
/// 不能出现两条会话抢到同一个授权码、也不能出现审计链序号冲突。
/// </summary>
public sealed class ConcurrencyTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 9, 0, 0, TimeSpan.FromHours(8));
    private readonly TestDb _db = new();
    private readonly PackageBuilder _pkg = new();

    public ConcurrencyTests()
    {
        TrustedKeyRepository.Add(_db.Store, _pkg.TrustedKey(), "admin", Now);
        _pkg.GeneratedAt = Now.AddHours(-1);
        _pkg.AddDetainee("D-001", "李四");
        for (var i = 0; i < 40; i++)
        {
            _pkg.AddLawyer(CertFor(i), $"律师{i:00}");
        }
        var r = new RosterImporter(_db.Store).Import(new ImportOptions(_pkg.Build(), "admin", Now));
        Assert.True(r.Ok, r.Message);
    }

    private static string CertFor(int i) => "11101202010" + (100000 + i).ToString();

    [Fact]
    public async Task ParallelWindowsProduceUniqueAuthorizationCodesAndIntactChain()
    {
        var tasks = Enumerable.Range(0, 40).Select(i => Task.Run(() =>
        {
            var engine = new VerificationEngine(_db.Store);
            var sessions = new SessionService(_db.Store);
            var request = new VerificationRequest
            {
                CertNo = CertFor(i), Name = $"律师{i:00}", DetaineeNo = "D-001",
                Commission = CommissionKind.Entrustment, PhotoVerdict = PhotoVerdict.Match,
                Officer = $"民警{i % 4}", Window = $"{i % 4 + 1}号窗口", Now = Now,
            };
            var decision = engine.Evaluate(request);
            var session = sessions.Start(request, decision, Guid.NewGuid().ToString("N"));
            var result = sessions.Authorize(new AuthorizeRequest(session.SessionId,
                request.Officer, null, null, null, null, "secret", Now));
            return (decision.Outcome, result.Succeeded, result.Code);
        })).ToArray();

        var results = await Task.WhenAll(tasks);

        Assert.All(results, r => Assert.True(r.Outcome == VerificationOutcome.Verified,
            "全部应为核验通过：" + r.Outcome));
        Assert.All(results, r => Assert.True(r.Succeeded));

        var codes = results.Select(r => r.Code).ToList();
        Assert.Equal(codes.Count, codes.Distinct().Count());

        var report = AuditLog.Verify(_db.Store);
        Assert.True(report.Intact, report.Problem);

        // 每条会话都应有完整的 start + authorize 两条审计，
        // 加上 1 条导入与 1 条公钥登记 = 40*2 + 2
        Assert.Equal(40 + 40 + 2, report.Count);
    }

    [Fact]
    public async Task ReadOnlyQueriesDoNotBlockDuringWrites()
    {
        var writes = Enumerable.Range(0, 20).Select(i => Task.Run(() =>
        {
            var sessions = new SessionService(_db.Store);
            var engine = new VerificationEngine(_db.Store);
            var request = new VerificationRequest
            {
                CertNo = CertFor(i), Name = $"律师{i:00}", DetaineeNo = "D-001",
                Commission = CommissionKind.Entrustment, PhotoVerdict = PhotoVerdict.Match,
                Officer = "民警A", Window = "1号", Now = Now,
            };
            sessions.Start(request, engine.Evaluate(request), Guid.NewGuid().ToString("N"));
        })).ToArray();

        var reads = Enumerable.Range(0, 40).Select(_ => Task.Run(() =>
        {
            // 忙等待期间窗口仍在实时查询名册
            var found = RosterRepository.Find(_db.Store, CertFor(0));
            var stamp = RosterRepository.GetStamp(_db.Store, RosterPolicy.Default, Now);
            Assert.NotNull(found);
            Assert.True(stamp.Exists);
        })).ToArray();

        await Task.WhenAll(writes.Concat(reads));
        Assert.Equal(20, new SessionService(_db.Store).Recent(100).Count);
    }

    public void Dispose()
    {
        _db.Dispose();
        _pkg.Dispose();
    }
}
