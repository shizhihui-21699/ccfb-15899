using System.Text.Json;
using DetentionVerify.Core;

namespace DetentionVerify.Tests;

public sealed class ImportTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 8, 0, 0, TimeSpan.FromHours(8));

    [Fact]
    public void SignedPackageImports()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        TrustedKeyRepository.Add(db.Store, pkg.TrustedKey(), "admin", Now);
        pkg.AddLawyer("11101202010123456", "张伟", id: "110101199001011237")
            .AddDetainee("D-001", "李四");
        var dir = pkg.Build();

        var result = new RosterImporter(db.Store).Import(new ImportOptions(dir, "admin", Now));

        Assert.True(result.Ok, result.Message);
        Assert.Equal(1, result.RecordCount);
        Assert.NotNull(RosterRepository.Find(db.Store, "11101202010123456"));
    }

    [Fact]
    public void TamperedRecordsRejectedAndOldRosterSurvives()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        TrustedKeyRepository.Add(db.Store, pkg.TrustedKey(), "admin", Now);
        pkg.AddLawyer("11101202010123456", "张伟").AddDetainee("D-001", "李四");
        var first = pkg.Build();
        Assert.True(new RosterImporter(db.Store).Import(new ImportOptions(first, "admin", Now)).Ok);

        // 篡改：签名之后替换 records.jsonl
        pkg.Sequence = 2;
        pkg.SnapshotId = "snap-002";
        pkg.AddLawyer("11101202010999999", "伪造者");
        pkg.Build();
        File.WriteAllText(Path.Combine(first, "records.jsonl"),
            File.ReadAllText(Path.Combine(first, "records.jsonl")).Replace("伪造者", "换个人"));

        var result = new RosterImporter(db.Store).Import(new ImportOptions(first, "admin", Now.AddHours(1)));

        Assert.False(result.Ok);
        Assert.Contains("哈希", result.Message);
        // 旧名册仍在，窗口不受影响
        var stamp = RosterRepository.GetActiveStamp(db.Store);
        Assert.Equal("snap-001", stamp!.Value.SnapshotId);
        Assert.NotNull(RosterRepository.Find(db.Store, "11101202010123456"));
    }

    [Fact]
    public void SignatureFromUntrustedKeyRejected()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        // 未登记 TrustedKey
        pkg.AddLawyer("11101202010123456", "张伟");
        var dir = pkg.Build();

        var result = new RosterImporter(db.Store).Import(new ImportOptions(dir, "admin", Now));

        Assert.False(result.Ok);
        Assert.Contains("信任列表", result.Message);
    }

    [Fact]
    public void CorruptSignatureRejected()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        TrustedKeyRepository.Add(db.Store, pkg.TrustedKey(), "admin", Now);
        pkg.AddLawyer("11101202010123456", "张伟");
        var dir = pkg.Build(corruptSignature: true);

        var result = new RosterImporter(db.Store).Import(new ImportOptions(dir, "admin", Now));

        Assert.False(result.Ok);
        Assert.Contains("签名校验失败", result.Message);
    }

    [Fact]
    public void StaleSequenceRejectedButRollbackAcceptedWhenExplicit()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        TrustedKeyRepository.Add(db.Store, pkg.TrustedKey(), "admin", Now);

        pkg.Sequence = 5;
        pkg.SnapshotId = "snap-005";
        pkg.AddLawyer("11101202010123456", "张伟");
        var oldDir = pkg.Build();
        Assert.True(new RosterImporter(db.Store).Import(new ImportOptions(oldDir, "admin", Now)).Ok);

        using var pkg2 = new PackageBuilder { Sequence = 4, SnapshotId = "snap-004" };
        TrustedKeyRepository.Add(db.Store, pkg2.TrustedKey(), "admin", Now);
        pkg2.AddLawyer("11101202010777777", "李娜");
        var newDir = pkg2.Build();

        var rejected = new RosterImporter(db.Store).Import(new ImportOptions(newDir, "admin", Now));
        Assert.False(rejected.Ok);
        Assert.Contains("序号", rejected.Message);

        var accepted = new RosterImporter(db.Store).Import(
            new ImportOptions(newDir, "admin", Now) { AcceptStaleSequence = true });
        Assert.True(accepted.Ok, accepted.Message);
        Assert.Equal("snap-004", RosterRepository.GetActiveStamp(db.Store)!.Value.SnapshotId);
    }

    [Fact]
    public void DuplicateCertNumbersFailLoudly()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        TrustedKeyRepository.Add(db.Store, pkg.TrustedKey(), "admin", Now);
        pkg.AddLawyer("11101202010123456", "张伟")
           .AddLawyer("11101202010123456", "另一个张伟");
        var dir = pkg.Build();

        var result = new RosterImporter(db.Store).Import(new ImportOptions(dir, "admin", Now));

        Assert.False(result.Ok);
        Assert.Contains("重复证号", result.Message);
    }

    [Fact]
    public void IdNumberIsNeverStoredInPlaintext()
    {
        using var db = new TestDb();
        using var pkg = new PackageBuilder();
        TrustedKeyRepository.Add(db.Store, pkg.TrustedKey(), "admin", Now);
        pkg.AddLawyer("11101202010123456", "张伟", id: "110101199001011237");
        var dir = pkg.Build();
        Assert.True(new RosterImporter(db.Store).Import(new ImportOptions(dir, "admin", Now)).Ok);

        db.Store.Dispose();
        var raw = File.ReadAllBytes(db.Path);
        var text = System.Text.Encoding.UTF8.GetString(raw);
        Assert.DoesNotContain("110101199001011237", text);
        db.Store.Dispose();
    }
}
