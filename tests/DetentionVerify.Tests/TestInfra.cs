using System.Security.Cryptography;
using System.Text.Json;
using DetentionVerify.Core;

namespace DetentionVerify.Tests;

/// <summary>测试用导入包生成器：模拟省级平台导出并签名。</summary>
public sealed class PackageBuilder : IDisposable
{
    public string Root { get; }
    public string KeyId { get; set; } = "test-key-2026";
    public ECDsa Key { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public long Sequence { get; set; } = 1;
    public string SnapshotId { get; set; } = "snap-001";
    public DateTimeOffset GeneratedAt { get; set; } = new(2026, 11, 24, 6, 0, 0, TimeSpan.FromHours(8));
    public List<LawyerRecord> Lawyers { get; } = [];
    public List<DetaineeRecord> Detainees { get; } = [];
    public Dictionary<string, byte[]> Photos { get; } = new();
    public string? SourceSystem { get; set; } = "省律师管理平台";

    public PackageBuilder()
    {
        Root = Path.Combine(Path.GetTempPath(), "dv-pkg-" + Guid.NewGuid().ToString("N")[..10]);
        Directory.CreateDirectory(Root);
    }

    public TrustedKey TrustedKey() => new(KeyId, PackageSignature.AlgorithmEcdsaP256,
        Convert.ToBase64String(Key.ExportSubjectPublicKeyInfo()), "测试密钥");

    public PackageBuilder AddLawyer(string certNo, string name, string firm = "示例律师事务所",
        LicenseStatus status = LicenseStatus.Active, string? id = null, string? photoSha = null,
        DateOnly? validTo = null)
    {
        Lawyers.Add(new LawyerRecord
        {
            CertNo = certNo,
            Name = name,
            FirmName = firm,
            LicenseStatus = status,
            IdNumber = id,
            PhotoSha256 = photoSha,
            ValidFrom = new DateOnly(2020, 1, 1),
            ValidTo = validTo,
        });
        return this;
    }

    public PackageBuilder AddDetainee(string no, string name, string status = "在押", string? restricted = null)
    {
        Detainees.Add(new DetaineeRecord { DetaineeNo = no, Name = name, Status = status, Room = "301", RestrictedReason = restricted });
        return this;
    }

    public PackageBuilder AddPhoto(string sha, byte[] bytes)
    {
        Photos[sha] = bytes;
        return this;
    }

    public string Build(bool corruptSignature = false, bool tamperRecords = false)
    {
        var recordsPath = Path.Combine(Root, "records.jsonl");
        using (var w = new StreamWriter(recordsPath))
        {
            foreach (var l in Lawyers)
                w.WriteLine(JsonSerializer.Serialize(l, JsonDefaults.Options));
        }
        if (tamperRecords) File.AppendAllText(recordsPath, ""); // 占位；真正的篡改见 TamperAfterSign

        var detaineesPath = Path.Combine(Root, "detainees.json");
        File.WriteAllText(detaineesPath, JsonSerializer.Serialize(Detainees, JsonDefaults.Options));

        var photosDir = Path.Combine(Root, "photos");
        Directory.CreateDirectory(photosDir);
        foreach (var (sha, bytes) in Photos) File.WriteAllBytes(Path.Combine(photosDir, sha + ".jpg"), bytes);

        var manifest = new RosterManifest
        {
            SnapshotId = SnapshotId,
            GeneratedAt = GeneratedAt,
            SourceSystem = SourceSystem,
            Sequence = Sequence,
            KeyId = KeyId,
            RecordCount = Lawyers.Count,
            DetaineeCount = Detainees.Count,
            RecordsSha256 = PackageSignature.HashFile(recordsPath),
            DetaineesSha256 = PackageSignature.HashFile(detaineesPath),
        };
        var manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonDefaults.Options);
        File.WriteAllBytes(Path.Combine(Root, "manifest.json"), manifestBytes);

        var sig = PackageSignature.Sign(Key, manifestBytes);
        if (corruptSignature) sig[0] ^= 0xFF;
        File.WriteAllBytes(Path.Combine(Root, "manifest.sig"), sig);
        return Root;
    }

    public void Dispose()
    {
        try { Directory.Delete(Root, true); } catch { /* 临时目录清理失败不影响测试结论 */ }
        Key.Dispose();
    }
}

public sealed class TestDb : IDisposable
{
    public string Path { get; }
    public SqliteStore Store { get; }
    public FixedClock Clock { get; } = new(new DateTimeOffset(2026, 11, 24, 9, 30, 0, TimeSpan.FromHours(8)));

    public TestDb()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "dv-" + Guid.NewGuid().ToString("N")[..10] + ".db");
        Store = new SqliteStore(Path);
    }

    public void Dispose()
    {
        Store.Dispose();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
        {
            try { File.Delete(Path + suffix); } catch { }
        }
    }
}
