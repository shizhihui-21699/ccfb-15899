using DetentionVerify.Core;
using DetentionVerify.Desktop;

namespace DetentionVerify.Tests;

public sealed class AppointmentAndExportTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 9, 0, 0, TimeSpan.FromHours(8));
    private const string Cert = "11101202010123456";

    private readonly TestDb _db = new();
    private readonly PackageBuilder _pkg = new();

    public AppointmentAndExportTests()
    {
        TrustedKeyRepository.Add(_db.Store, _pkg.TrustedKey(), "admin", Now);
        _pkg.GeneratedAt = Now.AddHours(-1);
    }

    private void ImportWithAppointments()
    {
        _pkg.AddLawyer(Cert, "张伟").AddDetainee("D-001", "李四");
        var dir = _pkg.Build();

        var appts = new[]
        {
            new AppointmentRecord
            {
                AppointmentId = "A-1", Date = DateOnly.FromDateTime(Now.DateTime), Slot = "09:00",
                CertNo = Cert, LawyerName = "张伟", DetaineeNo = "D-001", DetaineeName = "李四",
                Commission = CommissionKind.Entrustment,
            },
        };
        File.WriteAllText(Path.Combine(dir, "appointments.json"), System.Text.Json.JsonSerializer.Serialize(appts, JsonDefaults.Options));

        // 重新签名以包含预约哈希
        var manifestPath = Path.Combine(dir, "manifest.json");
        var manifest = System.Text.Json.JsonSerializer.Deserialize<RosterManifest>(
            File.ReadAllBytes(manifestPath), JsonDefaults.Options)!;
        var withAppts = manifest with
        {
            AppointmentsSha256 = PackageSignature.HashFile(Path.Combine(dir, "appointments.json")),
        };
        var bytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(withAppts, JsonDefaults.Options);
        File.WriteAllBytes(manifestPath, bytes);
        File.WriteAllBytes(Path.Combine(dir, "manifest.sig"), PackageSignature.Sign(_pkg.Key, bytes));

        var result = new RosterImporter(_db.Store).Import(new ImportOptions(dir, "admin", Now));
        Assert.True(result.Ok, result.Message);
    }

    [Fact]
    public void AppointmentQueueReflectsAuthorization()
    {
        ImportWithAppointments();
        var repo = new AppointmentRepository(_db.Store);
        var date = DateOnly.FromDateTime(Now.DateTime);

        var before = repo.ForDate(date);
        Assert.Single(before);
        Assert.False(before[0].Done);
        Assert.Equal("pending", before[0].RowClass);

        var engine = new VerificationEngine(_db.Store);
        var sessions = new SessionService(_db.Store);
        var request = new VerificationRequest
        {
            CertNo = Cert, Name = "张伟", DetaineeNo = "D-001", Commission = CommissionKind.Entrustment,
            PhotoVerdict = PhotoVerdict.Match, Officer = "民警甲", Window = "1号", Now = Now,
        };
        var decision = engine.Evaluate(request);
        var session = sessions.Start(request, decision, Guid.NewGuid().ToString("N"));
        Assert.True(sessions.Authorize(new AuthorizeRequest(session.SessionId, "民警甲", null, null, null,
            null, "secret", Now)).Succeeded);

        var after = repo.ForDate(date);
        Assert.True(after[0].Done);
        Assert.Equal("done", after[0].RowClass);
        Assert.Equal(new QueueStats(1, 1, 0), repo.Stats(date));
    }

    [Fact]
    public void TamperedAppointmentFileIsRejected()
    {
        ImportWithAppointments();
        var dir = _pkg.Root;
        File.WriteAllText(Path.Combine(dir, "appointments.json"), "[]");

        using var db2 = new TestDb();
        TrustedKeyRepository.Add(db2.Store, _pkg.TrustedKey(), "admin", Now);
        var result = new RosterImporter(db2.Store).Import(new ImportOptions(dir, "admin", Now));
        Assert.False(result.Ok);
        Assert.Contains("预约名单哈希", result.Message);
    }

    [Fact]
    public void ExportProducesCsvAndVerifiableAuditPack()
    {
        ImportWithAppointments();
        var engine = new VerificationEngine(_db.Store);
        var sessions = new SessionService(_db.Store);
        var request = new VerificationRequest
        {
            CertNo = Cert, Name = "张伟", DetaineeNo = "D-001", Commission = CommissionKind.Entrustment,
            PhotoVerdict = PhotoVerdict.Match, Officer = "民警甲", Window = "1号", Now = Now,
        };
        var decision = engine.Evaluate(request);
        var session = sessions.Start(request, decision, Guid.NewGuid().ToString("N"));
        sessions.Authorize(new AuthorizeRequest(session.SessionId, "民警甲", null, null, null, null, "secret", Now));

        var outDir = Path.Combine(Path.GetTempPath(), "dv-export-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            EvidenceExporter.ExportDay(_db.Store, DateOnly.FromDateTime(Now.DateTime), outDir, "民警甲");

            Assert.True(File.Exists(Path.Combine(outDir, "sessions-20261124.csv")));
            Assert.True(File.Exists(Path.Combine(outDir, "audit-20261124.jsonl")));
            Assert.True(File.Exists(Path.Combine(outDir, "README-20261124.txt")));

            var csv = File.ReadAllText(Path.Combine(outDir, "sessions-20261124.csv"));
            Assert.Contains("张伟", csv);
            Assert.Contains("核验通过", csv);

            var readme = File.ReadAllText(Path.Combine(outDir, "README-20261124.txt"));
            Assert.Contains("审计链完整性：完整", readme);
            Assert.Contains("链头哈希", readme);
        }
        finally
        {
            try { Directory.Delete(outDir, true); } catch { }
        }
    }

    [Fact]
    public void CsvInjectionInLawyerNameIsNeutralized()
    {
        _pkg.AddLawyer(Cert, "=cmd|'/c calc'!A1").AddDetainee("D-001", "李四");
        var dir = _pkg.Build();
        Assert.True(new RosterImporter(_db.Store).Import(new ImportOptions(dir, "admin", Now)).Ok);

        var engine = new VerificationEngine(_db.Store);
        var sessions = new SessionService(_db.Store);
        var request = new VerificationRequest
        {
            CertNo = Cert, Name = "=cmd|'/c calc'!A1", DetaineeNo = "D-001",
            Commission = CommissionKind.Entrustment, PhotoVerdict = PhotoVerdict.Match,
            Officer = "民警甲", Window = "1号", Now = Now,
        };
        sessions.Start(request, engine.Evaluate(request), Guid.NewGuid().ToString("N"));

        var outDir = Path.Combine(Path.GetTempPath(), "dv-export-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            EvidenceExporter.ExportDay(_db.Store, DateOnly.FromDateTime(Now.DateTime), outDir, "民警甲");
            var csv = File.ReadAllText(Path.Combine(outDir, "sessions-20261124.csv"));
            Assert.DoesNotContain("\n=cmd", csv);
            Assert.DoesNotContain(",=", csv);
            Assert.Contains("'=cmd", csv);
        }
        finally
        {
            try { Directory.Delete(outDir, true); } catch { }
        }
    }

    public void Dispose()
    {
        _db.Dispose();
        _pkg.Dispose();
    }
}
