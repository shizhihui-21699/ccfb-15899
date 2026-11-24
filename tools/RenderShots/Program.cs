using System.Security.Cryptography;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using DetentionVerify.Core;
using DetentionVerify.Desktop;
using DetentionVerify.Desktop.ViewModels;
using DetentionVerify.Desktop.Views;

namespace DetentionVerify.RenderShots;

/// <summary>
/// 开发期截图工具：用真实窗口 + 真实数据渲染 PNG，便于在没有图形环境的机器上检查界面。
/// 不属于产品的一部分，仅用于视觉回归。
/// </summary>
internal static class Program
{
    private static string _dataDir = "";

    public static int Main(string[] args)
    {
        var outDir = args.Length > 0 ? args[0] : "/tmp/dv-shots";
        Directory.CreateDirectory(outDir);

        _dataDir = Path.Combine(Path.GetTempPath(), "dv-shot-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_dataDir);
        Environment.SetEnvironmentVariable("DETENTION_VERIFY_DATA", _dataDir);

        AppBuilder.Configure<App>()
            .UseSkia()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .WithInterFont()
            .SetupWithoutStarting();

        SeedData();

        var services = AppServices.Create();
        services.Settings.OfficerName = "王建国";
        services.Settings.WindowName = "2号窗口";

        var vm = new MainWindowViewModel(services);
        var window = new MainWindow { DataContext = vm, Width = 1500, Height = 940 };
        window.Show();

        Pump(window);
        Capture(window, Path.Combine(outDir, "01-idle.png"));

        // 场景一：正常通过
        vm.CertNo = "11101202010123456";
        vm.LawyerNameInput = "张伟";
        vm.DetaineeNoInput = "D-001";
        vm.VerifyCommand.Execute(null);
        Pump(window, 12);
        Capture(window, Path.Combine(outDir, "02-verified.png"));

        // 场景二：冒用他人证件
        vm.ClearCommand.Execute(null);
        vm.CertNo = "11101202010123456";
        vm.LawyerNameInput = "李鬼";
        vm.DetaineeNoInput = "D-001";
        vm.VerifyCommand.Execute(null);
        Pump(window, 12);
        Capture(window, Path.Combine(outDir, "03-blocked-impersonation.png"));

        // 场景三：正常路径终点——签发授权
        vm.ClearCommand.Execute(null);
        vm.CertNo = "13101201910234567";
        vm.LawyerNameInput = "陈晓梅";
        vm.DetaineeNoInput = "D-002";
        vm.VerifyCommand.Execute(null);
        Pump(window, 10);
        vm.AuthorizeCommand.Execute(null);
        Pump(window, 14);
        Capture(window, Path.Combine(outDir, "03-authorized.png"));

        // 场景四：名册过期 + 查无此人 → 人工复核
        vm.ClearCommand.Execute(null);
        ReimportStale();
        vm.RefreshRosterCommand.Execute(null);
        vm.CertNo = "11101202010999999";
        vm.LawyerNameInput = "赵某";
        vm.DetaineeNoInput = "D-001";
        vm.VerifyCommand.Execute(null);
        Pump(window, 12);
        Capture(window, Path.Combine(outDir, "04-stale-manual-review.png"));


        // 场景四：管理员窗口
        var admin = new AdminWindow { DataContext = new AdminViewModel(services), Width = 1080, Height = 820 };
        admin.Show();
        Pump(admin, 10);
        Capture(admin, Path.Combine(outDir, "05-admin.png"));

        admin.Close();

        Console.WriteLine("shots -> " + outDir);
        return 0;
    }

    private static void Pump(Window window, int frames = 4)
    {
        for (var i = 0; i < frames; i++)
        {
            Dispatcher.UIThread.RunJobs();
            AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        }
    }

    private static void Capture(Window window, string path)
    {
        using var frame = window.CaptureRenderedFrame();
        if (frame is null)
        {
            Console.WriteLine("capture failed: " + path);
            return;
        }
        frame.Save(path);
    }

    private static void SeedData()
    {
        using var store = new SqliteStore(Path.Combine(_dataDir, "detention-verify.db"));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trusted = new TrustedKey("prov-key-2026", PackageSignature.AlgorithmEcdsaP256,
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), "省律师管理平台");
        TrustedKeyRepository.Add(store, trusted, "管理员", DateTimeOffset.Now.AddDays(-1));

        var pkgDir = Path.Combine(Path.GetTempPath(), "dv-shot-pkg-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(pkgDir, "photos"));

        var photoBytes = MakePlaceholderPhoto();
        var photoSha = PackageSignature.ComputeSha256Hex(photoBytes);
        File.WriteAllBytes(Path.Combine(pkgDir, "photos", photoSha + ".png"), photoBytes);

        var lawyers = new List<LawyerRecord>
        {
            new()
            {
                CertNo = "11101202010123456", Name = "张伟", FirmName = "北京京华律师事务所",
                FirmCode = "31110000", LicenseStatus = LicenseStatus.Active,
                ValidFrom = new DateOnly(2018, 3, 1), ValidTo = new DateOnly(2027, 2, 28),
                IdNumber = "110101199001011237", PhotoSha256 = photoSha, Region = "北京",
                UpdatedAt = DateTimeOffset.Now.AddDays(-1),
            },
            new()
            {
                CertNo = "13101201910234567", Name = "陈晓梅", FirmName = "上海正衡律师事务所",
                LicenseStatus = LicenseStatus.Active, ValidFrom = new DateOnly(2019, 6, 1),
                ValidTo = new DateOnly(2026, 12, 20), IdNumber = "310101198805054321",
                Region = "上海", UpdatedAt = DateTimeOffset.Now.AddDays(-1),
            },
            new()
            {
                CertNo = "14401201510987654", Name = "刘振海", FirmName = "广州南方律师事务所",
                LicenseStatus = LicenseStatus.Suspended, ValidFrom = new DateOnly(2015, 1, 1),
                ValidTo = new DateOnly(2026, 11, 30), Region = "广东",
                UpdatedAt = DateTimeOffset.Now.AddDays(-1),
            },
        };

        var detainees = new List<DetaineeRecord>
        {
            new() { DetaineeNo = "D-001", Name = "李国强", Room = "第三监区 305", Status = "在押" },
            new() { DetaineeNo = "D-002", Name = "周敏", Room = "第二监区 208", Status = "在押" },
            new() { DetaineeNo = "D-003", Name = "赵永强", Room = "第三监区 311", Status = "在押",
                    RestrictedReason = "涉黑案件，侦查阶段禁止会见" },
        };

        var today = DateOnly.FromDateTime(DateTime.Now);
        var appointments = new List<AppointmentRecord>
        {
            new() { AppointmentId = "A-001", Date = today, Slot = "09:00", CertNo = "11101202010123456",
                    LawyerName = "张伟", DetaineeNo = "D-001", DetaineeName = "李国强",
                    Commission = CommissionKind.Entrustment, CommissionNo = "WT-2026-0912" },
            new() { AppointmentId = "A-002", Date = today, Slot = "09:30", CertNo = "13101201910234567",
                    LawyerName = "陈晓梅", DetaineeNo = "D-002", DetaineeName = "周敏",
                    Commission = CommissionKind.LegalAid, CommissionNo = "FY-2026-3341" },
            new() { AppointmentId = "A-003", Date = today, Slot = "10:00", CertNo = "14401201510987654",
                    LawyerName = "刘振海", DetaineeNo = "D-003", DetaineeName = "赵永强",
                    Commission = CommissionKind.Entrustment },
            new() { AppointmentId = "A-004", Date = today, Slot = "10:30", CertNo = "11101202010999999",
                    LawyerName = "孙丽", DetaineeNo = "D-002", DetaineeName = "周敏",
                    Commission = CommissionKind.OfficialLetter },
        };

        WritePackage(pkgDir, key, 1, "snap-20261124-a", lawyers, detainees, appointments,
            DateTimeOffset.Now.AddHours(-2), photoSha, photoBytes);

        var result = new RosterImporter(store).Import(
            new ImportOptions(pkgDir, "管理员", DateTimeOffset.Now));
        Console.WriteLine("seed import: " + result.Message);

        // 预置一条已授权的流水，让右侧列表不是空的
        var engine = new VerificationEngine(store);
        var sessions = new SessionService(store);
        var req = new VerificationRequest
        {
            CertNo = "13101201910234567", Name = "陈晓梅", DetaineeNo = "D-002",
            Commission = CommissionKind.LegalAid, PhotoVerdict = PhotoVerdict.Match,
            Officer = "王建国", Window = "2号窗口", Now = DateTimeOffset.Now.AddMinutes(-40),
        };
        var decision = engine.Evaluate(req);
        var session = sessions.Start(req, decision, Guid.NewGuid().ToString("N"));
        sessions.Authorize(new AuthorizeRequest(session.SessionId, "王建国", null, null, null,
            "D-002", "shot-secret", DateTimeOffset.Now.AddMinutes(-39)));
    }

    private static void ReimportStale()
    {
        using var store = new SqliteStore(Path.Combine(_dataDir, "detention-verify.db"));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        TrustedKeyRepository.Add(store, new TrustedKey("stale-key", PackageSignature.AlgorithmEcdsaP256,
            Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), "省律师管理平台"),
            "管理员", DateTimeOffset.Now);

        var pkgDir = Path.Combine(Path.GetTempPath(), "dv-shot-pkg2-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(pkgDir, "photos"));
        var lawyers = new List<LawyerRecord>
        {
            new() { CertNo = "11101202010123456", Name = "张伟", FirmName = "北京京华律师事务所",
                    LicenseStatus = LicenseStatus.Active, ValidTo = new DateOnly(2027, 2, 28) },
        };
        var detainees = new List<DetaineeRecord>
        {
            new() { DetaineeNo = "D-001", Name = "李国强", Room = "第三监区 305", Status = "在押" },
        };

        WritePackage(pkgDir, key, 9, "snap-20261118-old", lawyers, detainees, [],
            DateTimeOffset.Now.AddDays(-6), null, null);

        var result = new RosterImporter(store).Import(new ImportOptions(pkgDir, "管理员", DateTimeOffset.Now));
        Console.WriteLine("stale import: " + result.Message);
    }

    private static void WritePackage(string dir, ECDsa key, long seq, string snapshotId,
        List<LawyerRecord> lawyers, List<DetaineeRecord> detainees, List<AppointmentRecord> appointments,
        DateTimeOffset generatedAt, string? photoSha, byte[]? photoBytes)
    {
        var recordsPath = Path.Combine(dir, "records.jsonl");
        File.WriteAllLines(recordsPath, lawyers.Select(l => JsonSerializer.Serialize(l, JsonDefaults.Options)));
        var detaineesPath = Path.Combine(dir, "detainees.json");
        File.WriteAllText(detaineesPath, JsonSerializer.Serialize(detainees, JsonDefaults.Options));

        string? apptSha = null;
        if (appointments.Count > 0)
        {
            var apptPath = Path.Combine(dir, "appointments.json");
            File.WriteAllText(apptPath, JsonSerializer.Serialize(appointments, JsonDefaults.Options));
            apptSha = PackageSignature.HashFile(apptPath);
        }

        var manifest = new RosterManifest
        {
            SnapshotId = snapshotId,
            GeneratedAt = generatedAt,
            SourceSystem = "省律师管理平台",
            Sequence = seq,
            KeyId = "",
            RecordCount = lawyers.Count,
            DetaineeCount = detainees.Count,
            RecordsSha256 = PackageSignature.HashFile(recordsPath),
            DetaineesSha256 = PackageSignature.HashFile(detaineesPath),
            AppointmentsSha256 = apptSha,
        };

        manifest = manifest with
        {
            KeyId = seq == 9 ? "stale-key" : "prov-key-2026",
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonDefaults.Options);
        File.WriteAllBytes(Path.Combine(dir, "manifest.json"), bytes);
        File.WriteAllBytes(Path.Combine(dir, "manifest.sig"), PackageSignature.Sign(key, bytes));

        if (photoBytes is not null && photoSha is not null)
            File.WriteAllBytes(Path.Combine(dir, "photos", photoSha + ".png"), photoBytes);
    }

    /// <summary>生成一张占位“证件照”，不需要真实人脸素材。</summary>
    private static byte[] MakePlaceholderPhoto()
    {
        const int w = 300, h = 380;
        var pixels = new byte[w * h * 4];
        for (var y = 0; y < h; y++)
        {
            for (var x = 0; x < w; x++)
            {
                var i = (y * w + x) * 4;
                // BGRA，浅蓝证件照背景 + 简单人形轮廓
                byte b = 205, g = 225, r = 235;
                var cx = w / 2.0;
                var headR = w * 0.21;
                var dy = y - h * 0.36;
                var dx = x - cx;
                if (dx * dx + dy * dy < headR * headR)
                {
                    b = 170; g = 150; r = 138;
                }
                else if (y > h * 0.62)
                {
                    var shoulder = (x - cx) / (w * 0.42);
                    if (Math.Abs(shoulder) < 1)
                    {
                        b = 96; g = 78; r = 62;
                    }
                }
                pixels[i] = b;
                pixels[i + 1] = g;
                pixels[i + 2] = r;
                pixels[i + 3] = 255;
            }
        }

        using var ms = new MemoryStream();
        var writeable = new WriteableBitmap(new PixelSize(w, h), new Vector(96, 96),
            Avalonia.Platform.PixelFormat.Bgra8888, Avalonia.Platform.AlphaFormat.Opaque);
        using (var fb = writeable.Lock())
        {
            System.Runtime.InteropServices.Marshal.Copy(pixels, 0, fb.Address, pixels.Length);
        }
        writeable.Save(ms);
        return ms.ToArray();
    }
}
