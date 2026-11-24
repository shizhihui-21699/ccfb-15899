using System.Diagnostics;
using DetentionVerify.Core;

namespace DetentionVerify.Tests;

/// <summary>
/// 性能回归。会见高峰时多个窗口同时签发授权，若写路径退化成 OS 级锁争抢，
/// 单次操作会从毫秒级劣化到数百毫秒，窗口直接排长队。
/// 这些阈值刻意设得很宽松（只拦截数量级劣化），避免机器差异导致误报。
/// </summary>
public sealed class PerformanceRegressionTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 9, 0, 0, TimeSpan.FromHours(8));
    private readonly TestDb _db = new();
    private readonly PackageBuilder _pkg = new();

    public PerformanceRegressionTests()
    {
        TrustedKeyRepository.Add(_db.Store, _pkg.TrustedKey(), "admin", Now);
        _pkg.GeneratedAt = Now.AddHours(-1);
        _pkg.AddDetainee("D-001", "李四");
        for (var i = 0; i < 32; i++) _pkg.AddLawyer(CertFor(i), $"律师{i:00}");
        var r = new RosterImporter(_db.Store).Import(new ImportOptions(_pkg.Build(), "admin", Now));
        Assert.True(r.Ok, r.Message);
    }

    private static string CertFor(int i) => "11101202010" + (200000 + i).ToString();

    /// <summary>
    /// 缓存已修的教训：曾因每次 Open() 都执行 PRAGMA journal_mode=WAL，
    /// 以及缺少进程内写闸门，32 并发写耗时约 12 秒。修复后为亚秒级。
    /// </summary>
    [Fact]
    public void ParallelAuthorizationStaysFarBelowQueueingThreshold()
    {
        var threads = Enumerable.Range(0, 32).Select(i => new Thread(() =>
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
            Assert.Equal(VerificationOutcome.Verified, decision.Outcome);
            var session = sessions.Start(request, decision, Guid.NewGuid().ToString("N"));
            var result = sessions.Authorize(new AuthorizeRequest(session.SessionId,
                request.Officer, null, null, null, null, "perf-secret", Now));
            Assert.True(result.Succeeded, result.Message);
        })).ToArray();

        var sw = Stopwatch.StartNew();
        foreach (var t in threads) t.Start();
        foreach (var t in threads) t.Join();
        sw.Stop();

        // 32 次完整“核验+登记+授权+两条审计”。宽限到 5 秒；回归时会远超此值（曾为 12 秒以上）。
        Assert.True(sw.ElapsedMilliseconds < 5000,
            $"32 个并发窗口完成核验授权耗时 {sw.ElapsedMilliseconds} ms，已超过 5 秒门槛，疑似写路径退化");

        Assert.True(AuditLog.Verify(_db.Store).Intact);
    }

    [Fact]
    public void RepeatedReadsAreCheap()
    {
        var engine = new VerificationEngine(_db.Store);
        var request = new VerificationRequest
        {
            CertNo = CertFor(0), Name = "律师00", DetaineeNo = "D-001",
            Commission = CommissionKind.Entrustment, PhotoVerdict = PhotoVerdict.Match,
            Officer = "民警甲", Window = "1号", Now = Now,
        };

        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 100; i++)
        {
            var d = engine.Evaluate(request);
            Assert.Equal(VerificationOutcome.Verified, d.Outcome);
        }
        sw.Stop();

        // 100 次纯查询（含名册时效、证号、在押、当日重复检查）。目标远低于 2 秒。
        Assert.True(sw.ElapsedMilliseconds < 2000,
            $"100 次核验耗时 {sw.ElapsedMilliseconds} ms，查询路径可能引入了不必要的写或锁");
    }

    public void Dispose()
    {
        _db.Dispose();
        _pkg.Dispose();
    }
}
