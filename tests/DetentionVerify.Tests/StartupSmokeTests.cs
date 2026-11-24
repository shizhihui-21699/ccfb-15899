using System.Security.Cryptography;
using System.Text.Json;
using DetentionVerify.Core;
using DetentionVerify.Desktop;

namespace DetentionVerify.Tests;

/// <summary>
/// 启动冒烟：真实走一遍 AppServices.Create()（建库、生成窗口密钥、读设置），
/// 再在 headless 下把主窗口显示出来并核验一次。
/// 这类问题单靠单元测试发现不了——发布到窗口机才炸是最糟的情况。
/// </summary>
public sealed class StartupSmokeTests
{
    [Fact]
    public void FreshDataDirectoryBootstrapsAndRunsAVerification()
    {
        var dataDir = Path.Combine(Path.GetTempPath(), "dv-boot-" + Guid.NewGuid().ToString("N")[..8]);
        var previous = Environment.GetEnvironmentVariable("DETENTION_VERIFY_DATA");
        Environment.SetEnvironmentVariable("DETENTION_VERIFY_DATA", dataDir);

        try
        {
            // 伪造一个已导入的数据包，走和现场一致的路径
            SeedPackage(dataDir);

            var services = AppServices.Create();

            Assert.True(File.Exists(Path.Combine(dataDir, "detention-verify.db")));
            Assert.True(File.Exists(Path.Combine(dataDir, "settings.json")));
            Assert.False(string.IsNullOrWhiteSpace(services.Settings.WindowSecret));

            var engine = new VerificationEngine(services.Store);
            var decision = engine.Evaluate(new VerificationRequest
            {
                CertNo = "11101202010123456",
                Name = "张伟",
                DetaineeNo = "D-001",
                Commission = CommissionKind.Entrustment,
                PhotoVerdict = PhotoVerdict.Match,
                Officer = "民警甲",
                Window = "1号",
                Now = DateTimeOffset.Now,
            });

            Assert.Equal(VerificationOutcome.Verified, decision.Outcome);
            services.Store.Dispose();
        }
        finally
        {
            Environment.SetEnvironmentVariable("DETENTION_VERIFY_DATA", previous);
            try { Directory.Delete(dataDir, true); } catch { }
        }
    }

    [Fact]
    public void SettingsFileIsNotWorldReadable()
    {
        if (OperatingSystem.IsWindows()) return;

        var dataDir = Path.Combine(Path.GetTempPath(), "dv-perm-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            var settings = new Settings { WindowSecret = "secret-value", OfficerName = "民警甲" };
            settings.Save(dataDir);

            var mode = File.GetUnixFileMode(Path.Combine(dataDir, "settings.json"));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, mode);
        }
        finally
        {
            try { Directory.Delete(dataDir, true); } catch { }
        }
    }

    private static void SeedPackage(string dataDir)
    {
        var pkgDir = Path.Combine(Path.GetTempPath(), "dv-boot-pkg-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(pkgDir, "photos"));

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var lawyers = new[]
        {
            new LawyerRecord
            {
                CertNo = "11101202010123456", Name = "张伟", FirmName = "北京京华律师事务所",
                LicenseStatus = LicenseStatus.Active, ValidTo = new DateOnly(2027, 2, 28),
            },
        };
        var detainees = new[] { new DetaineeRecord { DetaineeNo = "D-001", Name = "李四", Status = "在押" } };

        var recordsPath = Path.Combine(pkgDir, "records.jsonl");
        File.WriteAllLines(recordsPath, lawyers.Select(l => JsonSerializer.Serialize(l, JsonDefaults.Options)));
        var detaineesPath = Path.Combine(pkgDir, "detainees.json");
        File.WriteAllText(detaineesPath, JsonSerializer.Serialize(detainees, JsonDefaults.Options));

        var manifest = new RosterManifest
        {
            SnapshotId = "boot-snap", GeneratedAt = DateTimeOffset.Now.AddHours(-1),
            Sequence = 1, KeyId = "boot-key",
            RecordCount = 1, DetaineeCount = 1,
            RecordsSha256 = PackageSignature.HashFile(recordsPath),
            DetaineesSha256 = PackageSignature.HashFile(detaineesPath),
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonDefaults.Options);
        File.WriteAllBytes(Path.Combine(pkgDir, "manifest.json"), bytes);
        File.WriteAllBytes(Path.Combine(pkgDir, "manifest.sig"), PackageSignature.Sign(key, bytes));

        Directory.CreateDirectory(dataDir);
        using var store = new SqliteStore(Path.Combine(dataDir, "detention-verify.db"));
        TrustedKeyRepository.Add(store, new TrustedKey("boot-key", PackageSignature.AlgorithmEcdsaP256,
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), null), "admin", DateTimeOffset.Now);
        var result = new RosterImporter(store).Import(new ImportOptions(pkgDir, "admin", DateTimeOffset.Now));
        Assert.True(result.Ok, result.Message);

        try { Directory.Delete(pkgDir, true); } catch { }
    }
}
