using System.Globalization;

namespace DetentionVerify.Core;

/// <summary>
/// 核验规则引擎。设计原则（与一线窗口的取证现实对齐）：
/// 1) 只有“名册明确记载且状态不允许”才判禁止；名册里查不到，只能说“本机数据未覆盖”，
///    因为内网名册是定期导入的，查不到很可能是数据未更新，而非伪造。把两者混为一谈会天天误伤真律师。
/// 2) 自动判定只在证据充分时下“禁止”结论；其余一律交人工复核，并强制留痕。
/// 3) 每一条结论都带可读依据，民警要能在几秒内向当事人解释“为什么不行”。
/// </summary>
public sealed class VerificationEngine(SqliteStore store, RosterPolicy? policy = null)
{
    private readonly RosterPolicy _policy = policy ?? RosterPolicy.Default;

    public VerificationDecision Evaluate(VerificationRequest req)
    {
        var checks = new List<CheckResult>();
        var today = DateOnly.FromDateTime(req.Now.Date);
        var certNo = LicenseNumber.Normalize(req.CertNo);
        var roster = RosterRepository.GetStamp(store, _policy, req.Now);

        // ---- 0. 基础可用性：名册本身 ----
        if (!roster.Exists)
        {
            checks.Add(new CheckResult("ROSTER_MISSING", Severity.Block, "本机尚无生效名册",
                "请先由管理员导入省级律师管理平台的签名数据包，否则无法核验任何身份"));
            return Build(checks, null, null, null, roster, []);
        }

        if (roster.IsDegraded)
        {
            checks.Add(new CheckResult("ROSTER_DEGRADED", Severity.Fail, "名册已过期，数据可能不可信",
                $"当前快照生成于 {roster.GeneratedAt:yyyy-MM-dd HH:mm}，已 {(int)roster.Age.TotalHours} 小时未更新。必须交人工核实"));
        }
        else if (roster.IsStale)
        {
            checks.Add(new CheckResult("ROSTER_STALE", Severity.Caution, "名册数据偏旧",
                $"上次同步于 {roster.GeneratedAt:yyyy-MM-dd HH:mm}，已 {(int)roster.Age.TotalHours} 小时。如查无此人，优先按数据未更新处理"));
        }

        // ---- 1. 证号结构 ----
        if (certNo.Length == 0)
        {
            checks.Add(new CheckResult("CERT_EMPTY", Severity.Block, "未录入执业证号"));
            return Build(checks, null, null, null, roster, []);
        }

        var structural = LicenseNumber.StructuralIssue(certNo, today);
        if (structural is not null)
        {
            // 结构异常只是提示：编号规则有历史变体，不能据此认定伪造。
            checks.Add(new CheckResult("CERT_FORMAT", Severity.Caution, "证号格式异常", structural));
        }

        // ---- 2. 名册查询 ----
        var lawyer = RosterRepository.Find(store, certNo);
        LawyerRecord? record = lawyer?.ToRecord();
        PhotoRef? photo = null;

        if (lawyer is null)
        {
            var near = RosterRepository.NearMiss(store, certNo);
            var byName = !string.IsNullOrWhiteSpace(req.Name) &&
                         RosterRepository.ExistsByNameAndFirm(store, LicenseNumber.NormalizeName(req.Name), req.FirmName?.Trim());

            if (roster.IsDegraded)
            {
                checks.Add(new CheckResult("CERT_NOT_IN_ROSTER", Severity.Fail,
                    "名册中查无此证号，但名册已过期",
                    "无法区分“证号有误/伪造”与“名册未更新”。必须由值班长人工核实后方可会见"));
            }
            else
            {
                checks.Add(new CheckResult("CERT_NOT_IN_ROSTER", Severity.Block,
                    "名册中无此执业证号",
                    near.Count > 0
                        ? $"相近证号：{string.Join("、", near)}。如属录入错误请更正后重查"
                        : "请核对执业证原件；若确认证号无误，该证可能为伪造或已注销未同步"));
            }

            if (byName && near.Count == 0)
            {
                checks.Add(new CheckResult("NAME_ONLY_MATCH", Severity.Caution, "同名律师存在但证号不符",
                    "证件姓名在本机名册中能查到，但证号不同——可能拿错证、也可能是冒用他人姓名，须核对原件"));
            }

            return Build(checks, record, null, null, roster, near);
        }

        // 名册命中本身就是最重要的一条正向依据：这是签名数据里真实存在的执业证，而不是结构像。
        checks.Add(new CheckResult("CERT_FOUND", Severity.Info, "执业证号在签名名册中可查",
            $"名册记载：{lawyer.Name} · {lawyer.FirmName ?? "律所未载"} · 快照 {roster.SnapshotId}"));

        // ---- 3. 姓名一致性（防冒用） ----
        var inputName = LicenseNumber.NormalizeName(req.Name);
        if (inputName.Length > 0 && inputName != lawyer.Name)
        {
            checks.Add(new CheckResult("NAME_MISMATCH", Severity.Block, "出示人与证载律师不一致",
                $"名册证载姓名「{lawyer.Name}」，录入「{inputName}」。此为冒用他人执业证的典型特征"));
        }
        else if (inputName.Length > 0)
        {
            checks.Add(new CheckResult("NAME_MATCH", Severity.Info, "姓名与名册记载一致", lawyer.Name));
        }

        // ---- 4. 律所一致性 ----
        var inputFirm = req.FirmName?.Trim();
        if (!string.IsNullOrEmpty(inputFirm) && !string.IsNullOrEmpty(lawyer.FirmName) &&
            !string.Equals(inputFirm, lawyer.FirmName, StringComparison.Ordinal))
        {
            checks.Add(new CheckResult("FIRM_MISMATCH", Severity.Caution, "律所与名册不符",
                $"名册记载「{lawyer.FirmName}」。律师转所后名册未更新属常见情况，请核对介绍信与执业证"));
        }
        else if (!string.IsNullOrEmpty(inputFirm) && !string.IsNullOrEmpty(lawyer.FirmName))
        {
            checks.Add(new CheckResult("FIRM_MATCH", Severity.Info, "律所与名册一致", lawyer.FirmName));
        }

        // ---- 5. 执业状态 ----
        switch (lawyer.Status)
        {
            case LicenseStatus.Revoked:
                checks.Add(new CheckResult("LICENSE_REVOKED", Severity.Block, "执业证已被吊销",
                    "吊销期间不得以律师身份会见在押人员"));
                break;
            case LicenseStatus.Suspended:
                checks.Add(new CheckResult("LICENSE_SUSPENDED", Severity.Block, "执业证处于停止执业期间",
                    $"停止执业期至 {lawyer.ValidTo?.ToString("yyyy-MM-dd") ?? "未注明"}，期间不得会见"));
                break;
            case LicenseStatus.Expired:
                checks.Add(new CheckResult("LICENSE_EXPIRED", Severity.Block, "执业证已过期"));
                break;
            case LicenseStatus.Unknown:
                checks.Add(new CheckResult("LICENSE_UNKNOWN", Severity.Fail, "名册未记载执业状态",
                    "上游数据缺失，须人工核实执业证当前是否有效"));
                break;
            case LicenseStatus.Active:
                checks.Add(new CheckResult("LICENSE_ACTIVE", Severity.Info, "执业状态正常",
                    lawyer.ValidTo is { } vt ? $"名册记载执业有效期至 {vt:yyyy-MM-dd}" : "名册记载为正常执业"));
                break;
        }

        if (lawyer.ValidTo is { } validTo && validTo < today)
        {
            var found = checks.Any(c => c.Code is "LICENSE_EXPIRED" or "LICENSE_SUSPENDED" or "LICENSE_REVOKED");
            if (!found)
                checks.Add(new CheckResult("LICENSE_PAST_VALIDITY", Severity.Block, "执业证已过有效期",
                    $"有效期至 {validTo:yyyy-MM-dd}，已过期 {(today.DayNumber - validTo.DayNumber)} 天"));
        }
        else if (lawyer.ValidTo is { } soon && soon.DayNumber - today.DayNumber is >= 0 and <= 30)
        {
            checks.Add(new CheckResult("LICENSE_EXPIRING", Severity.Info, "执业证即将到期",
                $"有效期至 {soon:yyyy-MM-dd}，请提醒律师及时换证"));
        }

        // ---- 6. 人证对照 ----
        switch (req.PhotoVerdict)
        {
            case PhotoVerdict.Mismatch:
                checks.Add(new CheckResult("PHOTO_MISMATCH", Severity.Block, "人证对照明显不符",
                    "照片与出示人差异明显，涉嫌冒用他人执业证，应立即报告值班领导"));
                break;
            case PhotoVerdict.Doubtful:
                checks.Add(new CheckResult("PHOTO_DOUBTFUL", Severity.Fail, "人证对照存疑",
                    "照片与本人存在差异（证件照年代久、整容、体重变化均可能导致）。须由第二人复核"));
                break;
            case PhotoVerdict.NotPerformed:
                checks.Add(new CheckResult("PHOTO_NOT_CHECKED", Severity.Caution, "未完成人证对照",
                    "必须比对执业证照片与本人，并在此登记比对结论"));
                break;
            case PhotoVerdict.Match:
                checks.Add(new CheckResult("PHOTO_MATCH", Severity.Info, "人证对照相符",
                    "由窗口民警比对名册照片与本人后确认"));
                break;
        }

        // ---- 7. 身份证号辅助核对 ----
        var idInput = LicenseNumber.Normalize(req.IdNumber);
        if (idInput.Length > 0)
        {
            var issue = LicenseNumber.IdNumberIssue(idInput);
            if (issue is not null)
            {
                checks.Add(new CheckResult("ID_INVALID", Severity.Caution, "身份证号不合规", issue));
            }
            else
            {
                var salt = store.GetOrCreateSalt();
                var hash = IdHashing.Hash(idInput, salt);
                using var conn = store.OpenConnection();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT id_hash FROM lawyer WHERE cert_no=$c";
                cmd.Parameters.AddWithValue("$c", certNo);
                var stored = cmd.ExecuteScalar() as string;
                if (stored is { Length: > 0 })
                {
                    if (!string.Equals(stored, hash, StringComparison.Ordinal))
                        checks.Add(new CheckResult("ID_MISMATCH", Severity.Block, "身份证号与名册不符",
                            "证号对应的是另一人，涉嫌冒用执业证"));
                    else
                        checks.Add(new CheckResult("ID_MATCH", Severity.Info, "身份证号与名册一致"));
                }
            }
        }
        else if (!string.IsNullOrWhiteSpace(req.IdLast6) && lawyer.IdLast6 is { Length: 6 } last6)
        {
            var provided = LicenseNumber.Normalize(req.IdLast6);
            if (provided.Length == 6)
            {
                checks.Add(provided == last6
                    ? new CheckResult("ID_LAST6_MATCH", Severity.Info, "身份证后 6 位一致")
                    : new CheckResult("ID_LAST6_MISMATCH", Severity.Fail, "身份证后 6 位不符",
                        "与名册登记不一致，须核对身份证原件并交复核"));
            }
        }

        // ---- 8. 委托手续 ----
        if (req.Commission == CommissionKind.None)
        {
            checks.Add(new CheckResult("COMMISSION_MISSING", Severity.Block, "未提交委托手续",
                "无委托书/法律援助公函/单位介绍信，不得安排会见"));
        }
        else
        {
            var label = req.Commission switch
            {
                CommissionKind.Entrustment => "委托书",
                CommissionKind.LegalAid => "法律援助公函",
                _ => "单位介绍信",
            };
            checks.Add(new CheckResult("COMMISSION_PRESENT", Severity.Info, $"已收取{label}",
                string.IsNullOrWhiteSpace(req.CommissionNo) ? null : $"手续编号 {req.CommissionNo}"));
        }

        // ---- 9. 在押人员 ----
        // 只按编号查。req.Name 是律师姓名，不能拿来匹配在押人员——
        // 同姓同名会让系统把一个陌生人当成会见对象，这是不该有的“聪明”。
        DetaineeRecord? detainee = !string.IsNullOrWhiteSpace(req.DetaineeNo)
            ? RosterRepository.FindDetainee(store, req.DetaineeNo)
            : null;

        if (!string.IsNullOrWhiteSpace(req.DetaineeNo))
        {
            if (detainee is null)
            {
                checks.Add(new CheckResult("DETAINEE_NOT_FOUND", Severity.Fail, "在押人员编号查无此人",
                    roster.IsDegraded
                        ? "且名册已过期，可能是新入所人员尚未同步，须人工核实"
                        : "请核对编号，或该人已出所"));
            }
            else
            {
                if (detainee.Status != "在押")
                {
                    checks.Add(new CheckResult("DETAINEE_NOT_IN_CUSTODY", Severity.Block,
                        $"该人员当前状态为「{detainee.Status}」", "已不在本所羁押，不能安排会见"));
                }
                if (!string.IsNullOrWhiteSpace(detainee.RestrictedReason))
                {
                    checks.Add(new CheckResult("DETAINEE_RESTRICTED", Severity.Block, "该在押人员被限制会见",
                        detainee.RestrictedReason));
                }
                else if (detainee.Status == "在押")
                {
                    checks.Add(new CheckResult("DETAINEE_OK", Severity.Info, "在押人员状态正常",
                        $"{detainee.Name} · {detainee.Room ?? "监室未载"}"));
                }
            }
        }
        else
        {
            checks.Add(new CheckResult("DETAINEE_UNSPECIFIED", Severity.Caution, "未指定会见对象",
                "须登记被会见在押人员，以便关联同案与串供风险"));
        }

        // ---- 10. 当日重复会见（串供风险线索） ----
        var dayStart = new DateTimeOffset(req.Now.Year, req.Now.Month, req.Now.Day, 0, 0, 0, req.Now.Offset);
        var dayEnd = dayStart.AddDays(1);
        if (detainee is not null && RosterRepository.HasOpenAuthorizationForDetainee(
                store, certNo, detainee.DetaineeNo, dayStart, dayEnd))
        {
            checks.Add(new CheckResult("SAME_DAY_REPEAT", Severity.Caution, "该律师今日已会见同一在押人员",
                "同一律师同日多次会见同一人属异常，请确认是否为换班、补充材料或他人借证"));
        }

        // ---- 11. 照片素材 ----
        // 区分两种缺失：上游名册本来就没有照片（Info，靠实体证与身份证人工核对即可），
        // 与名册有照片但文件没导进来（Caution，说明导入包不完整，本可以给人看却没给）。
        photo = RosterRepository.GetPhoto(store, lawyer.PhotoSha256);
        if (photo is null && !string.IsNullOrEmpty(lawyer.PhotoSha256))
        {
            checks.Add(new CheckResult("PHOTO_UNAVAILABLE", Severity.Caution, "名册登记的照片未随包导入",
                "请管理员检查导入包 photos 目录；本次只能以执业证原件照片人工核对"));
        }
        else if (photo is null)
        {
            checks.Add(new CheckResult("PHOTO_ABSENT", Severity.Info, "名册未提供该律师照片",
                "以执业证原件照片与身份证人工核对"));
        }

        return Build(checks, record, detainee, photo, roster, []);
    }

    private static VerificationDecision Build(List<CheckResult> checks, LawyerRecord? lawyer,
        DetaineeRecord? detainee, PhotoRef? photo, RosterStamp roster, IReadOnlyList<string> nearMiss)
    {
        var outcome = checks.Any(c => c.Severity == Severity.Block)
            ? VerificationOutcome.Blocked
            : checks.Any(c => c.Severity == Severity.Fail)
                ? VerificationOutcome.NeedsManualReview
                : checks.Any(c => c.Severity == Severity.Caution)
                    ? VerificationOutcome.VerifiedWithCaution
                    : VerificationOutcome.Verified;

        // 展示顺序：最严重的在前，民警先看到结论性依据。
        var ordered = checks.OrderByDescending(c => c.Severity).ToList();

        return new VerificationDecision
        {
            Outcome = outcome,
            Checks = ordered,
            Lawyer = lawyer,
            Detainee = detainee,
            Photo = photo,
            Roster = roster,
            NearMissCertNos = nearMiss,
        };
    }
}
