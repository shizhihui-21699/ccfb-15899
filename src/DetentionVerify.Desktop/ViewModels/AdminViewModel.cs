using System.Collections.ObjectModel;
using System.Security.Cryptography;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DetentionVerify.Core;

namespace DetentionVerify.Desktop.ViewModels;

/// <summary>
/// 管理员视图：导入、密钥、审计、导出。窗口民警看不到这里，避免高峰误操作替换名册。
/// </summary>
public sealed partial class AdminViewModel : ObservableObject
{
    private readonly AppServices _services;

    public AdminViewModel(AppServices services)
    {
        _services = services;
        AdminName = services.Settings.OfficerName;
        Refresh();
    }

    [ObservableProperty] private string _adminName = "";
    [ObservableProperty] private string _packageDirectory = "";
    [ObservableProperty] private string _importStatus = "请选择省级平台导出的签名包目录";
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _keyStatus = "";
    [ObservableProperty] private string _newKeyId = "";
    [ObservableProperty] private string _newKeyPublicPem = "";
    [ObservableProperty] private string _newKeyLabel = "";
    [ObservableProperty] private string _auditStatus = "";
    [ObservableProperty] private bool _auditIntact;
    [ObservableProperty] private string _exportStatus = "";
    [ObservableProperty] private string _newKeyExpiry = "";

    public ObservableCollection<string> Keys { get; } = [];
    public ObservableCollection<AuditRowViewModel> AuditRows { get; } = [];

    public string RosterSummary { get; private set; } = "";

    [RelayCommand]
    private void Refresh()
    {
        var stamp = RosterRepository.GetStamp(_services.Store, _services.Policy, DateTimeOffset.Now);
        RosterSummary = stamp.Exists
            ? $"当前名册：快照 {stamp.SnapshotId} · 生成于 {stamp.GeneratedAt:yyyy-MM-dd HH:mm} · " +
              $"{(int)stamp.Age.TotalHours} 小时前 · {stamp.RecordCount} 名律师"
            : "当前无生效名册";
        OnPropertyChanged(nameof(RosterSummary));

        Keys.Clear();
        foreach (var k in TrustedKeyRepository.List(_services.Store))
        {
            var validity = k.NotAfter is { } na ? $"，有效至 {na:yyyy-MM-dd}" : "";
            Keys.Add($"{k.KeyId} · {k.Algorithm} · {k.Label ?? "未命名"}{validity}");
        }
        KeyStatus = Keys.Count == 0
            ? "尚未登记任何签名公钥——导入会被拒绝，这是有意的"
            : $"已登记 {Keys.Count} 个签名公钥";

        RefreshAudit();
    }

    [RelayCommand]
    private void RefreshAudit()
    {
        AuditRows.Clear();
        foreach (var e in AuditLog.Read(_services.Store, 200))
            AuditRows.Add(new AuditRowViewModel(e));

        var report = AuditLog.Verify(_services.Store);
        AuditIntact = report.Intact;
        AuditStatus = report.Intact
            ? $"审计链完整：{report.Count} 条事件，链头 {report.HeadHash[..16]}…"
            : $"审计链异常：{report.Problem}";
    }

    [RelayCommand]
    private async Task ImportAsync()
    {
        if (string.IsNullOrWhiteSpace(PackageDirectory))
        {
            ImportStatus = "请先选择导入包目录";
            return;
        }
        if (string.IsNullOrWhiteSpace(AdminName))
        {
            ImportStatus = "请填写操作人姓名，导入操作会记入审计";
            return;
        }

        IsBusy = true;
        try
        {
            var result = await Task.Run(() => _services.Importer.Import(
                new ImportOptions(PackageDirectory.Trim(), AdminName, DateTimeOffset.Now)));

            var lines = new List<string> { (result.Ok ? "✓ " : "✗ ") + result.Message };
            if (result.Warnings is { Count: > 0 })
                lines.AddRange(result.Warnings.Select(w => "⚠ " + w));
            if (result.Errors is { Count: > 1 })
                lines.AddRange(result.Errors.Skip(1).Select(e => "· " + e));
            ImportStatus = string.Join("\n", lines);

            Refresh();
        }
        catch (Exception ex)
        {
            ImportStatus = "导入失败：" + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void AddKey()
    {
        if (string.IsNullOrWhiteSpace(NewKeyId) || string.IsNullOrWhiteSpace(NewKeyPublicPem))
        {
            KeyStatus = "请填写密钥编号与公钥 PEM";
            return;
        }
        if (string.IsNullOrWhiteSpace(AdminName))
        {
            KeyStatus = "请填写操作人姓名";
            return;
        }

        try
        {
            // 只接受公钥：私钥留在省级平台，本机永远不该有签发能力。
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(NewKeyPublicPem.Trim());
            var der = ecdsa.ExportSubjectPublicKeyInfo();

            DateTimeOffset? notAfter = null;
            if (DateTime.TryParse(NewKeyExpiry, out var parsed))
                notAfter = new DateTimeOffset(parsed);

            TrustedKeyRepository.Add(_services.Store, new TrustedKey(
                NewKeyId.Trim(), PackageSignature.AlgorithmEcdsaP256,
                Convert.ToBase64String(der), string.IsNullOrWhiteSpace(NewKeyLabel) ? null : NewKeyLabel.Trim(),
                NotAfter: notAfter), AdminName, DateTimeOffset.Now);

            NewKeyId = "";
            NewKeyPublicPem = "";
            NewKeyLabel = "";
            NewKeyExpiry = "";
            Refresh();
            KeyStatus = "公钥已登记";
        }
        catch (CryptographicException)
        {
            KeyStatus = "公钥格式无法识别，请粘贴 PEM（-----BEGIN PUBLIC KEY-----）";
        }
    }

    [RelayCommand]
    private async Task ExportAsync()
    {
        var dir = Path.Combine(_services.Settings.DataDirectory, "exports",
            DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss"));
        try
        {
            await Task.Run(() => EvidenceExporter.ExportDay(_services.Store,
                DateOnly.FromDateTime(DateTime.Now), dir,
                string.IsNullOrWhiteSpace(AdminName) ? "未署名" : AdminName));
            ExportStatus = "已导出到：" + dir;
        }
        catch (Exception ex)
        {
            ExportStatus = "导出失败：" + ex.Message;
        }
    }
}

public sealed class AuditRowViewModel(AuditEvent e)
{
    public string Seq => e.Seq.ToString();
    public string Time => e.OccurredAt.ToLocalTime().ToString("MM-dd HH:mm:ss");
    public string Category => e.Category;
    public string Actor => e.Actor;
    public string Subject => e.Subject.Length > 16 ? e.Subject[..16] + "…" : e.Subject;
    public string HashShort => e.Hash[..12] + "…";

    public string CategoryText => e.Category switch
    {
        "roster.import" => "名册导入",
        "trustkey.add" => "登记公钥",
        "session.start" => "开始核验",
        "session.authorize" => "签发授权",
        "session.checkin" => "入所核销",
        "session.revoke" => "撤销会见",
        _ => e.Category,
    };
}
