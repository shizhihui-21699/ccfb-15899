using System.Security.Cryptography;
using System.Text.Json;
using DetentionVerify.Core;

namespace DetentionVerify.Tools;

/// <summary>
/// 名册签名包生成工具（模拟省级律师管理平台侧的导出程序）。
/// 放在内网之外的律师管理系统上运行：读取业务库导出 → 生成清单 → 用私钥签名。
/// 私钥只应存在于该侧，看守所内网侧永远只拿到公钥，无法伪造名册。
///
/// 用法：
///   roster-pack keygen --out prov-key.pem             生成一对密钥并输出公钥
///   roster-pack build --in ./export --out ./package \
///        --key prov-key.pem --keyid prov-key-2026 --seq 42 --snapshot snap-20261124
///   roster-pack verify --package ./package --public prov-key.pub.pem
/// </summary>
internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0) { Usage(); return 1; }
        try
        {
            return args[0] switch
            {
                "keygen" => KeyGen(Opts(args)),
                "build" => Build(Opts(args)),
                "verify" => VerifyPackage(Opts(args)),
                _ => Unknown(args[0]),
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("错误：" + ex.Message);
            return 1;
        }
    }

    private static int Unknown(string cmd)
    {
        Console.Error.WriteLine($"未知命令：{cmd}");
        Usage();
        return 1;
    }

    private static void Usage()
    {
        Console.WriteLine("""
            名册签名包工具

              keygen  --out <私钥.pem> [--pub <公钥.pem>]
                      生成 ECDSA P-256 密钥对。私钥留在本机，公钥交看守所导入。

              build   --in <导出目录> --out <输出目录> --key <私钥.pem>
                      --keyid <密钥编号> --seq <序号> --snapshot <快照编号>
                      [--source <来源系统>] [--generated <ISO8601 时间>]
                      [--prev <上一快照编号>]
                      导出目录需包含 records.jsonl、detainees.json、
                      可选 appointments.json 与 photos/ 目录。

              verify  --package <包目录> --public <公钥.pem>
                      导入前自检，确认包能被看守所侧接受。
            """);
    }

    private static int KeyGen(Dictionary<string, string> o)
    {
        var outPath = Require(o, "out");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(outPath, key.ExportECPrivateKeyPem());
        TryRestrict(outPath);
        var pubPath = o.GetValueOrDefault("pub", Path.ChangeExtension(outPath, ".pub.pem"));
        File.WriteAllText(pubPath, key.ExportSubjectPublicKeyInfoPem());
        Console.WriteLine($"私钥：{outPath}（妥善保管，泄露等于任何人都能伪造名册）");
        Console.WriteLine($"公钥：{pubPath}（此文件交看守所管理员登记）");
        return 0;
    }

    private static int Build(Dictionary<string, string> o)
    {
        var inDir = Require(o, "in");
        var outDir = Require(o, "out");
        var keyPath = Require(o, "key");
        var keyId = Require(o, "keyid");
        var snapshot = Require(o, "snapshot");
        if (!long.TryParse(Require(o, "seq"), out var seq))
            throw new ArgumentException("--seq 必须是整数");

        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(keyPath));

        var recordsPath = Path.Combine(inDir, "records.jsonl");
        var detaineesPath = Path.Combine(inDir, "detainees.json");
        var apptsPath = Path.Combine(inDir, "appointments.json");
        if (!File.Exists(recordsPath)) throw new FileNotFoundException("导出目录缺少 records.jsonl");
        if (!File.Exists(detaineesPath)) throw new FileNotFoundException("导出目录缺少 detainees.json");

        // 先自检：解析失败的数据绝不能签进包里，否则看守所窗口直接不可用。
        var recordCount = 0;
        var certs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines(recordsPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var rec = JsonSerializer.Deserialize<LawyerRecord>(line, JsonDefaults.Options)
                      ?? throw new InvalidDataException("records.jsonl 中存在空记录");
            var cert = LicenseNumber.Normalize(rec.CertNo);
            if (cert.Length != 17)
                throw new InvalidDataException($"证号 {rec.CertNo} 不是 17 位");
            if (!certs.Add(cert))
                throw new InvalidDataException($"证号 {cert} 重复，上游数据有误");
            if (string.IsNullOrWhiteSpace(rec.Name))
                throw new InvalidDataException($"证号 {cert} 缺少姓名");
            recordCount++;
        }

        var detainees = JsonSerializer.Deserialize<List<DetaineeRecord>>(File.ReadAllText(detaineesPath), JsonDefaults.Options)
                        ?? throw new InvalidDataException("detainees.json 无法解析");

        Directory.CreateDirectory(outDir);
        var photosOut = Path.Combine(outDir, "photos");
        Directory.CreateDirectory(photosOut);

        // 照片按内容哈希命名，看守所侧会重新计算并核对，文件名不可信也无所谓。
        var photoShas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var photosIn = Path.Combine(inDir, "photos");
        if (Directory.Exists(photosIn))
        {
            foreach (var file in Directory.EnumerateFiles(photosIn))
            {
                var bytes = File.ReadAllBytes(file);
                var sha = PackageSignature.ComputeSha256Hex(bytes);
                File.WriteAllBytes(Path.Combine(photosOut, sha + Path.GetExtension(file).ToLowerInvariant()), bytes);
                photoShas.Add(sha);
            }
        }

        var missing = 0;
        foreach (var line in File.ReadLines(recordsPath))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var rec = JsonSerializer.Deserialize<LawyerRecord>(line, JsonDefaults.Options)!;
            if (!string.IsNullOrWhiteSpace(rec.PhotoSha256) && !photoShas.Contains(rec.PhotoSha256)) missing++;
        }
        if (missing > 0)
            Console.Error.WriteLine($"警告：{missing} 名律师的照片未找到，窗口将显示“名册无照片”");

        File.Copy(recordsPath, Path.Combine(outDir, "records.jsonl"), true);
        File.Copy(detaineesPath, Path.Combine(outDir, "detainees.json"), true);

        string? apptSha = null;
        if (File.Exists(apptsPath))
        {
            File.Copy(apptsPath, Path.Combine(outDir, "appointments.json"), true);
            apptSha = PackageSignature.HashFile(Path.Combine(outDir, "appointments.json"));
        }

        var manifest = new RosterManifest
        {
            SnapshotId = snapshot,
            GeneratedAt = o.TryGetValue("generated", out var g)
                ? DateTimeOffset.Parse(g)
                : DateTimeOffset.Now,
            SourceSystem = o.GetValueOrDefault("source", "省级律师管理平台"),
            Sequence = seq,
            KeyId = keyId,
            RecordCount = recordCount,
            DetaineeCount = detainees.Count,
            RecordsSha256 = PackageSignature.HashFile(Path.Combine(outDir, "records.jsonl")),
            DetaineesSha256 = PackageSignature.HashFile(Path.Combine(outDir, "detainees.json")),
            AppointmentsSha256 = apptSha,
            PrevSnapshotId = o.GetValueOrDefault("prev"),
        };

        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonDefaults.Options);
        File.WriteAllBytes(Path.Combine(outDir, "manifest.json"), manifestBytes);
        File.WriteAllBytes(Path.Combine(outDir, "manifest.sig"), PackageSignature.Sign(key, manifestBytes));

        Console.WriteLine($"已生成签名包：{outDir}");
        Console.WriteLine($"  快照 {snapshot}（序号 {seq}），{recordCount} 名律师、{detainees.Count} 名在押人员" +
                          (apptSha is null ? "" : "、含预约名单"));
        Console.WriteLine($"  清单 SHA-256：{PackageSignature.ComputeSha256Hex(manifestBytes)}");
        return 0;
    }

    private static int VerifyPackage(Dictionary<string, string> o)
    {
        var pkg = Require(o, "package");
        var pubPath = Require(o, "public");

        using var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(pubPath));

        var manifestBytes = File.ReadAllBytes(Path.Combine(pkg, "manifest.json"));
        var sig = File.ReadAllBytes(Path.Combine(pkg, "manifest.sig"));
        if (!key.VerifyData(manifestBytes, sig, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            Console.Error.WriteLine("签名校验失败");
            return 2;
        }

        var manifest = JsonSerializer.Deserialize<RosterManifest>(manifestBytes, JsonDefaults.Options)!;
        var checks = new (string Name, bool Ok, string Detail)[]
        {
            ("律师名册哈希", PackageSignature.HashFile(Path.Combine(pkg, "records.jsonl")) == manifest.RecordsSha256,
                manifest.RecordsSha256[..16]),
            ("在押名册哈希", PackageSignature.HashFile(Path.Combine(pkg, "detainees.json")) == manifest.DetaineesSha256,
                manifest.DetaineesSha256[..16]),
        };

        var allOk = true;
        foreach (var (name, ok, detail) in checks)
        {
            Console.WriteLine($"{(ok ? "✓" : "✗")} {name}  {detail}");
            allOk &= ok;
        }

        if (manifest.AppointmentsSha256 is { Length: > 0 })
        {
            var apptPath = Path.Combine(pkg, "appointments.json");
            var ok = File.Exists(apptPath) &&
                     PackageSignature.HashFile(apptPath) == manifest.AppointmentsSha256;
            Console.WriteLine($"{(ok ? "✓" : "✗")} 预约名单哈希  {manifest.AppointmentsSha256[..16]}");
            allOk &= ok;
        }

        Console.WriteLine(allOk
            ? $"包可被接受：快照 {manifest.SnapshotId}，序号 {manifest.Sequence}"
            : "包不可用：请检查文件是否完整");
        return allOk ? 0 : 2;
    }

    private static Dictionary<string, string> Opts(string[] args)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--")) continue;
            var name = args[i][2..];
            var value = i + 1 < args.Length && !args[i + 1].StartsWith("--") ? args[++i] : "true";
            dict[name] = value;
        }
        return dict;
    }

    private static string Require(Dictionary<string, string> o, string name) =>
        o.TryGetValue(name, out var v) && v != "true"
            ? v
            : throw new ArgumentException($"缺少参数 --{name}");

    private static void TryRestrict(string path)
    {
        if (OperatingSystem.IsWindows()) return;
        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
