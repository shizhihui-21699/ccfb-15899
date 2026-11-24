using System.Collections.ObjectModel;
using Avalonia.Media.Imaging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DetentionVerify.Core;

namespace DetentionVerify.Desktop.ViewModels;

public sealed partial class MainWindowViewModel : ObservableObject
{
    private readonly AppServices _services;

    /// <summary>供“管理”窗口复用同一套依赖（同一个库、同一个窗口密钥）。</summary>
    public AppServices Services => _services;

    public MainWindowViewModel(AppServices services)
    {
        _services = services;
        OfficerName = services.Settings.OfficerName;
        WindowName = services.Settings.WindowName;
        CommissionOptions = CommissionOption.All;
        PhotoVerdicts = PhotoVerdictOption.All;
        SelectedCommission = CommissionOptions[0];
        SelectedPhotoVerdict = PhotoVerdicts[0];
        RefreshRoster();
        RefreshQueue();
        RefreshRecent();
        StatusMessage = services.Settings.OfficerName.Length == 0
            ? "请先在“设置”中填写本窗口民警姓名，所有核验记录都会署你的名"
            : "输入执业证号后按 Enter，即可完成查询";
    }

    // ---------------- 窗口与人员 ----------------

    [ObservableProperty] private string _officerName = "";
    [ObservableProperty] private string _windowName = "";

    // ---------------- 录入 ----------------

    [ObservableProperty] private string _certNo = "";
    [ObservableProperty] private string _lawyerNameInput = "";
    [ObservableProperty] private string _firmNameInput = "";
    [ObservableProperty] private string _idNumberInput = "";
    [ObservableProperty] private string _detaineeNoInput = "";
    [ObservableProperty] private string _commissionNoInput = "";

    public IReadOnlyList<CommissionOption> CommissionOptions { get; }
    public IReadOnlyList<PhotoVerdictOption> PhotoVerdicts { get; }

    [ObservableProperty] private CommissionOption _selectedCommission;
    [ObservableProperty] private PhotoVerdictOption _selectedPhotoVerdict;

    // ---------------- 结果 ----------------

    [ObservableProperty] private VerificationDecision? _decision;
    [ObservableProperty] private Bitmap? _photo;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string? _cautionReason;
    [ObservableProperty] private string? _reviewOfficer;
    [ObservableProperty] private string? _reviewNote;
    [ObservableProperty] private string? _sessionId;
    [ObservableProperty] private string? _authorizedCode;
    [ObservableProperty] private string? _lastNearMissHint;

    public ObservableCollection<CheckItemViewModel> Checks { get; } = [];
    public ObservableCollection<SessionRowViewModel> Recent { get; } = [];
    public ObservableCollection<AppointmentRowViewModel> Queue { get; } = [];

    // ---------------- 预约队列 ----------------

    [ObservableProperty] private string _queueSummary = "";
    [ObservableProperty] private bool _hasAppointments;

    private void RefreshQueue()
    {
        Queue.Clear();
        var today = DateOnly.FromDateTime(DateTime.Now);
        var rows = new AppointmentRepository(_services.Store).ForDate(today);
        foreach (var row in rows) Queue.Add(new AppointmentRowViewModel(row, PickAppointment));
        var stats = new QueueStats(rows.Count, rows.Count(x => x.Done), rows.Count(x => !x.Done));
        HasAppointments = rows.Count > 0;
        QueueSummary = rows.Count == 0
            ? "今日无预约名单（可直接录入证号核验）"
            : $"预约 {stats.Total} 人 · 已办 {stats.Done} · 待办 {stats.Waiting}";
    }

    private void PickAppointment(AppointmentRowViewModel? row)
    {
        if (row is null) return;
        CertNo = row.CertNo;
        LawyerNameInput = row.LawyerName ?? "";
        DetaineeNoInput = row.DetaineeNo ?? "";
        CommissionNoInput = row.CommissionNo ?? "";
        SelectedCommission = CommissionOptions.FirstOrDefault(c => c.Kind == row.Commission) ?? CommissionOptions[0];
        StatusMessage = $"已带入预约：{row.DisplayName}，请核对执业证原件后按 Enter 核验";
    }

    // ---------------- 名册状态 ----------------

    [ObservableProperty] private string _rosterTitle = "";
    [ObservableProperty] private string _rosterDetail = "";
    [ObservableProperty] private bool _rosterIsWarning;
    [ObservableProperty] private bool _rosterIsDegraded;
    [ObservableProperty] private bool _rosterMissing;

    // ---- 人证对照单选（RadioButton 绑定布尔更稳，避免 ComboBox 误触） ----
    public bool VerdictMatch
    {
        get => SelectedPhotoVerdict.Verdict == PhotoVerdict.Match;
        set => SetVerdict(value, PhotoVerdict.Match);
    }

    public bool VerdictDoubtful
    {
        get => SelectedPhotoVerdict.Verdict == PhotoVerdict.Doubtful;
        set => SetVerdict(value, PhotoVerdict.Doubtful);
    }

    public bool VerdictMismatch
    {
        get => SelectedPhotoVerdict.Verdict == PhotoVerdict.Mismatch;
        set => SetVerdict(value, PhotoVerdict.Mismatch);
    }

    public bool VerdictNotPerformed
    {
        get => SelectedPhotoVerdict.Verdict == PhotoVerdict.NotPerformed;
        set => SetVerdict(value, PhotoVerdict.NotPerformed);
    }

    private void SetVerdict(bool on, PhotoVerdict verdict)
    {
        if (!on) return;
        SelectedPhotoVerdict = PhotoVerdicts.First(p => p.Verdict == verdict);
        OnPropertyChanged(nameof(VerdictMatch));
        OnPropertyChanged(nameof(VerdictDoubtful));
        OnPropertyChanged(nameof(VerdictMismatch));
        OnPropertyChanged(nameof(VerdictNotPerformed));
    }

    public string LawyerDisplayName => Decision?.Lawyer?.Name ?? (string.IsNullOrWhiteSpace(LawyerNameInput) ? "—" : LawyerNameInput);
    public string LawyerDisplayFirm => Decision?.Lawyer?.FirmName ?? FirmNameInput;
    public string LawyerDisplayCert => Decision?.Lawyer?.CertNo ?? LicenseNumber.Normalize(CertNo);
    public bool HasDetainee => Decision?.Detainee is not null;
    public string DetaineeDisplay => Decision?.Detainee is { } d
        ? string.IsNullOrWhiteSpace(d.Room) ? d.Name : $"{d.Name}  ·  {d.Room}"
        : "—";

    public bool HasNearMissHint => !string.IsNullOrEmpty(LastNearMissHint);

    public bool NeedsAnySupplement => RequiresCautionField || RequiresReviewFields;

    public bool IsOutcomeVerified => Decision?.Outcome == VerificationOutcome.Verified;
    public bool IsOutcomeCaution => Decision?.Outcome == VerificationOutcome.VerifiedWithCaution;
    public bool IsOutcomeReview => Decision?.Outcome == VerificationOutcome.NeedsManualReview;
    public bool IsOutcomeBlocked => Decision?.Outcome == VerificationOutcome.Blocked;

    public bool HasDecision => Decision is not null;
    public bool HasPhoto => Photo is not null;
    public bool HasAuthorizedCode => !string.IsNullOrEmpty(AuthorizedCode);
    /// <summary>
    /// 界面上是否显示“授权会见”。禁止会见一律不显示——即便值班领导另有处置，
    /// 也应当走线下审批另案记录，而不是让窗口在这块屏幕上点过去。
    /// </summary>
    public bool CanAuthorize => Decision is { Outcome: VerificationOutcome.Verified or VerificationOutcome.VerifiedWithCaution }
        || Decision is { Outcome: VerificationOutcome.NeedsManualReview };
    public bool RequiresReviewFields => Decision is { RequiresSupervisor: true } && Decision.Outcome == VerificationOutcome.NeedsManualReview;
    public bool RequiresCautionField => Decision is { RequiresCautionReason: true };
    public bool IsBlocked => Decision?.Outcome == VerificationOutcome.Blocked;

    public string OutcomeBadgeText => Decision?.Headline ?? "";

    /// <summary>按钮文案随结论变化，让民警一眼看出这一下是“直接授权”还是“复核后授权”。</summary>
    public string AuthorizeButtonText => Decision?.Outcome switch
    {
        VerificationOutcome.NeedsManualReview => "复核后授权  (F2)",
        VerificationOutcome.VerifiedWithCaution => "注明理由并授权  (F2)",
        _ => "授权会见  (F2)",
    };
    public string OutcomeBadgeClass => Decision?.Outcome switch
    {
        VerificationOutcome.Verified => "ok",
        VerificationOutcome.VerifiedWithCaution => "warn",
        VerificationOutcome.NeedsManualReview => "review",
        VerificationOutcome.Blocked => "block",
        _ => "idle",
    };

    // ---------------- 命令 ----------------

    [RelayCommand]
    private async Task VerifyAsync()
    {
        var cert = LicenseNumber.Normalize(CertNo);
        if (cert.Length == 0)
        {
            StatusMessage = "请先录入执业证号";
            return;
        }

        if (string.IsNullOrWhiteSpace(OfficerName))
        {
            StatusMessage = "请先在“设置”中填写本窗口民警姓名后再核验";
            return;
        }

        IsBusy = true;
        try
        {
            var now = DateTimeOffset.Now;
            var request = new VerificationRequest
            {
                CertNo = cert,
                Name = LawyerNameInput,
                FirmName = FirmNameInput,
                IdNumber = IdNumberInput,
                DetaineeNo = DetaineeNoInput,
                Commission = SelectedCommission.Kind,
                CommissionNo = CommissionNoInput,
                PhotoVerdict = SelectedPhotoVerdict.Verdict,
                Officer = OfficerName,
                Window = WindowName,
                Now = now,
            };

            var decision = await Task.Run(() => _services.Engine.Evaluate(request));

            Decision = decision;
            Checks.Clear();
            foreach (var c in decision.Checks) Checks.Add(new CheckItemViewModel(c));
            Photo = BuildPhoto(decision.Photo);

            LastNearMissHint = decision.NearMissCertNos.Count > 0
                ? $"相近证号：{string.Join("、", decision.NearMissCertNos)}（点击可替换）"
                : null;
            OnPropertyChanged(nameof(HasNearMissHint));

            // 每次核验都先落一条“查询”记录，即使最终未授权也要留痕。
            var session = _services.Sessions.Start(request, decision, Guid.NewGuid().ToString("N"));
            SessionId = session.SessionId;
            AuthorizedCode = null;
            CautionReason = null;
            ReviewOfficer = null;
            ReviewNote = null;

            StatusMessage = decision.Outcome switch
            {
                VerificationOutcome.Verified => "核验通过，按 F2 或点击“授权会见”",
                VerificationOutcome.VerifiedWithCaution => "存在疑点，须注明放行理由后可授权",
                VerificationOutcome.NeedsManualReview => "须第二名民警复核，填写复核人及核实情况",
                _ => "禁止会见——请核对原件并报告值班领导",
            };
            RefreshRecent();
            RefreshQueue();
            NotifyDecisionChanged();
        }
        catch (Exception ex)
        {
            StatusMessage = "核验失败：" + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private async Task AuthorizeAsync()
    {
        if (SessionId is null)
        {
            StatusMessage = "请先核验身份，再签发授权";
            return;
        }

        IsBusy = true;
        try
        {
            var result = await Task.Run(() => _services.Sessions.Authorize(new AuthorizeRequest(
                SessionId, OfficerName, CautionReason, ReviewOfficer, ReviewNote,
                string.IsNullOrWhiteSpace(DetaineeNoInput) ? null : DetaineeNoInput.Trim(),
                _services.Settings.WindowSecret, DateTimeOffset.Now)));

            if (!result.Succeeded)
            {
                StatusMessage = result.Message;
                return;
            }

            AuthorizedCode = result.Code;
            StatusMessage = $"已签发会见授权 {result.Code}，请交监区核对";
            OnPropertyChanged(nameof(HasAuthorizedCode));
            RefreshRecent();
            RefreshQueue();
        }
        catch (Exception ex)
        {
            StatusMessage = "授权失败：" + ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void Clear()
    {
        CertNo = "";
        LawyerNameInput = "";
        FirmNameInput = "";
        IdNumberInput = "";
        DetaineeNoInput = "";
        CommissionNoInput = "";
        Decision = null;
        Photo = null;
        SessionId = null;
        AuthorizedCode = null;
        CautionReason = null;
        ReviewOfficer = null;
        ReviewNote = null;
        LastNearMissHint = null;
        Checks.Clear();
        StatusMessage = "已清空，可录入下一位律师";
        NotifyDecisionChanged();
    }

    [RelayCommand]
    private void UseNearMiss(string? cert)
    {
        if (!string.IsNullOrWhiteSpace(cert)) CertNo = cert;
    }

    [RelayCommand]
    private void RefreshRoster()
    {
        var stamp = RosterRepository.GetStamp(_services.Store, _services.Policy, DateTimeOffset.Now);
        RosterMissing = !stamp.Exists;
        RosterIsDegraded = stamp.IsDegraded;
        RosterIsWarning = stamp.IsStale;

        if (!stamp.Exists)
        {
            RosterTitle = "尚无生效名册";
            RosterDetail = "请管理员导入省级律师管理平台的签名数据包后再开始核验";
        }
        else
        {
            var hours = (int)Math.Round(stamp.Age.TotalHours);
            RosterTitle = stamp.IsDegraded
                ? $"名册已过期 {hours} 小时"
                : stamp.IsStale ? $"名册偏旧 {hours} 小时" : $"名册正常（{hours} 小时前同步）";
            RosterDetail = $"快照 {stamp.SnapshotId} · 生成于 {stamp.GeneratedAt:MM-dd HH:mm} · {stamp.RecordCount} 名律师";
        }
    }

    [RelayCommand]
    private void RefreshRecent()
    {
        Recent.Clear();
        foreach (var s in _services.Sessions.Recent(30))
            Recent.Add(new SessionRowViewModel(s));
    }

    [RelayCommand]
    private void Revoke(SessionRowViewModel? row)
    {
        if (row is null || string.IsNullOrWhiteSpace(row.RevokeReason))
        {
            StatusMessage = "撤销会见必须填写原因（在右侧列表的输入框中填写）";
            return;
        }
        try
        {
            _services.Sessions.Revoke(row.SessionId, OfficerName, row.RevokeReason, DateTimeOffset.Now);
            StatusMessage = "已撤销该次会见，审计留有记录";
            RefreshRecent();
        }
        catch (Exception ex)
        {
            StatusMessage = "撤销失败：" + ex.Message;
        }
    }

    partial void OnCertNoChanged(string value) => StatusMessage = StatusMessage;

    partial void OnOfficerNameChanged(string value)
    {
        _services.Settings.OfficerName = value;
        TrySaveSettings();
    }

    partial void OnWindowNameChanged(string value)
    {
        _services.Settings.WindowName = value;
        TrySaveSettings();
    }

    private void TrySaveSettings()
    {
        try { _services.Settings.Save(); }
        catch (IOException) { /* 设置保存失败不影响核验 */ }
    }

    private static Bitmap? BuildPhoto(PhotoRef? photo)
    {
        if (photo is null) return null;
        try
        {
            using var ms = new MemoryStream(photo.Bytes);
            return new Bitmap(ms);
        }
        catch (Exception)
        {
            return null; // 损坏图片不应让整个核验失败
        }
    }

    private void NotifyDecisionChanged()
    {
        OnPropertyChanged(nameof(HasDecision));
        OnPropertyChanged(nameof(HasPhoto));
        OnPropertyChanged(nameof(LawyerDisplayName));
        OnPropertyChanged(nameof(LawyerDisplayFirm));
        OnPropertyChanged(nameof(LawyerDisplayCert));
        OnPropertyChanged(nameof(HasDetainee));
        OnPropertyChanged(nameof(DetaineeDisplay));
        OnPropertyChanged(nameof(HasNearMissHint));
        OnPropertyChanged(nameof(NeedsAnySupplement));
        OnPropertyChanged(nameof(IsOutcomeVerified));
        OnPropertyChanged(nameof(IsOutcomeCaution));
        OnPropertyChanged(nameof(IsOutcomeReview));
        OnPropertyChanged(nameof(IsOutcomeBlocked));
        OnPropertyChanged(nameof(CanAuthorize));
        OnPropertyChanged(nameof(RequiresReviewFields));
        OnPropertyChanged(nameof(RequiresCautionField));
        OnPropertyChanged(nameof(IsBlocked));
        OnPropertyChanged(nameof(OutcomeBadgeText));
        OnPropertyChanged(nameof(AuthorizeButtonText));
        OnPropertyChanged(nameof(OutcomeBadgeClass));
    }
}

public sealed record CommissionOption(CommissionKind Kind, string Label)
{
    public static readonly IReadOnlyList<CommissionOption> All =
    [
        new(CommissionKind.Entrustment, "委托书"),
        new(CommissionKind.LegalAid, "法律援助公函"),
        new(CommissionKind.OfficialLetter, "单位介绍信"),
    ];
}

public sealed record PhotoVerdictOption(PhotoVerdict Verdict, string Label, string Hint)
{
    public static readonly IReadOnlyList<PhotoVerdictOption> All =
    [
        new(PhotoVerdict.Match, "相符", "照片与本人一致"),
        new(PhotoVerdict.Doubtful, "存疑", "有差异，需第二人复核"),
        new(PhotoVerdict.Mismatch, "不符", "明显不是同一人"),
        new(PhotoVerdict.NotPerformed, "未比对", "尚未核对"),
    ];
}

public sealed class CheckItemViewModel(CheckResult result)
{
    public string Title => result.Title;
    public string? Detail => result.Detail;
    public bool HasDetail => !string.IsNullOrWhiteSpace(result.Detail);
    public string Code => result.Code;
    public string Level => result.Severity switch
    {
        Severity.Block => "block",
        Severity.Fail => "review",
        Severity.Caution => "warn",
        _ => "info",
    };
    public bool IsBlock => result.Severity == Severity.Block;
    public bool IsReview => result.Severity == Severity.Fail;
    public bool IsWarn => result.Severity == Severity.Caution;
    public string Glyph => result.Severity switch
    {
        Severity.Block => "✕",
        Severity.Fail => "!",
        Severity.Caution => "▲",
        _ => "✓",
    };
}

public sealed partial class SessionRowViewModel(SessionRecord record) : ObservableObject{
    public string SessionId { get; } = record.SessionId;
    public string Time => record.StartedAt.ToString("HH:mm:ss");
    public string Name { get; } = record.LawyerName ?? record.CertNo;
    public string CertNo { get; } = record.CertNo;
    public string Detainee { get; } = record.DetaineeName ?? record.DetaineeNo ?? "—";
    public string Code { get; } = record.AuthorizationCode ?? "";
    public string Summary { get; } = (record.Revoked ? "已撤销 · " : "") +
        (record.AuthorizationCode is { Length: > 0 } c ? "授权码 " + c + " · " : "") +
        (record.Outcome switch
        {
            "Verified" => "核验通过",
            "VerifiedWithCaution" => "有疑点放行",
            "NeedsManualReview" => "人工复核",
            _ => "禁止会见",
        });
    public bool Revoked { get; } = record.Revoked;
    public string StateText { get; } = record.Revoked ? "已撤销"
        : record.CheckedInAt is not null ? "已入所"
        : record.AuthorizedAt is not null ? "已授权"
        : "未授权";
    public string OutcomeClass { get; } = record.Outcome switch
    {
        "Verified" => "ok",
        "VerifiedWithCaution" => "warn",
        "NeedsManualReview" => "review",
        _ => "block",
    };

    [ObservableProperty] private string _revokeReason = "";
}

/// <summary>预约队列的一行。点一下即把证号/姓名/在押人员带入录入区，减少手打。</summary>
public sealed partial class AppointmentRowViewModel : CommunityToolkit.Mvvm.ComponentModel.ObservableObject
{
    private readonly AppointmentRow _row;
    private readonly Action<AppointmentRowViewModel> _pick;

    public AppointmentRowViewModel(AppointmentRow row, Action<AppointmentRowViewModel> pick)
    {
        _row = row;
        _pick = pick;
    }

    [CommunityToolkit.Mvvm.Input.RelayCommand]
    private void Pick() => _pick(this);

    public string AppointmentId => _row.AppointmentId;
    public string CertNo => _row.CertNo;
    public string LawyerName => _row.LawyerName ?? "";
    public string DetaineeNo => _row.DetaineeNo ?? "";
    public string DetaineeName => _row.DetaineeName ?? "";
    public string CommissionNo => _row.CommissionNo ?? "";
    public CommissionKind Commission => _row.Commission;
    public string DisplayName => _row.DisplayName;
    public string SlotText => _row.SlotText;
    public string Subtitle => _row.Subtitle;
    public bool Done => _row.Done;
    public bool NeedsRetry => !_row.Done && _row.Attempts > 0;

    public string Initial => _row.DisplayName.Length > 0 ? _row.DisplayName[..1] : "?";
}
