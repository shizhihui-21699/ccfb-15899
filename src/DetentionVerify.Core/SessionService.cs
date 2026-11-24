using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace DetentionVerify.Core;

/// <summary>
/// 审计日志：哈希链 + 可选 HMAC，保证“核验结果留存备查”不只是存了一条记录，
/// 而是能证明这条记录自写入后没有被改过、也没有被整段删除。
/// 说明：单机内网的威胁模型是“事后有人动数据库”，哈希链足以发现篡改；
/// 若需要对抗持有整机权限者的重算，应由上级机关定期抄走链头哈希做外部锚定。
/// </summary>
public static class AuditLog
{
    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    public static long Append(SqliteConnection conn, SqliteTransaction? tx, DateTimeOffset occurredAt,
        string category, string actor, string subject, string payloadJson)
    {
        using var head = conn.CreateCommand();
        head.Transaction = tx;
        head.CommandText = "SELECT seq,hash FROM audit_event ORDER BY seq DESC LIMIT 1";
        long seq = 1;
        string prev = Genesis;
        using (var r = head.ExecuteReader())
        {
            if (r.Read())
            {
                seq = r.GetInt64(0) + 1;
                prev = r.GetString(1);
            }
        }

        var stored = new
        {
            seq,
            occurredAt = occurredAt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            category,
            actor,
            subject,
            payloadJson,
        };
        var hash = ComputeHash(prev, stored);

        using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO audit_event(seq,occurred_at,category,actor,subject,payload_json,prev_hash,hash)
            VALUES($s,$t,$c,$a,$sub,$p,$ph,$h)
            """;
        cmd.Parameters.AddWithValue("$s", seq);
        cmd.Parameters.AddWithValue("$t", stored.occurredAt);
        cmd.Parameters.AddWithValue("$c", category);
        cmd.Parameters.AddWithValue("$a", actor);
        cmd.Parameters.AddWithValue("$sub", subject);
        cmd.Parameters.AddWithValue("$p", payloadJson);
        cmd.Parameters.AddWithValue("$ph", prev);
        cmd.Parameters.AddWithValue("$h", hash);
        cmd.ExecuteNonQuery();
        return seq;
    }

    private static string ComputeHash(string prev, object stored) =>
        Convert.ToHexStringLower(SHA256.HashData(
            Encoding.UTF8.GetBytes(prev + "\n" + JsonSerializer.Serialize(stored, JsonDefaults.Options))));

    public static IReadOnlyList<AuditEvent> Read(SqliteStore store, int limit = 200, long beforeSeq = long.MaxValue)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT seq,occurred_at,category,actor,subject,payload_json,prev_hash,hash
            FROM audit_event WHERE seq<$before ORDER BY seq DESC LIMIT $l
            """;
        cmd.Parameters.AddWithValue("$before", beforeSeq);
        cmd.Parameters.AddWithValue("$l", limit);
        using var r = cmd.ExecuteReader();
        var list = new List<AuditEvent>();
        while (r.Read())
        {
            list.Add(new AuditEvent(r.GetInt64(0),
                DateTimeOffset.Parse(r.GetString(1), CultureInfo.InvariantCulture),
                r.GetString(2), r.GetString(3), r.GetString(4), r.GetString(5), r.GetString(6), r.GetString(7)));
        }
        return list;
    }

    /// <summary>从链头往回逐条复算，定位首个断点。返回空表示完整。</summary>
    public static AuditIntegrityReport Verify(SqliteStore store)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT seq,occurred_at,category,actor,subject,payload_json,prev_hash,hash FROM audit_event ORDER BY seq";
        using var r = cmd.ExecuteReader();

        var expectedSeq = 1L;
        var prev = Genesis;
        long count = 0;
        string? firstProblem = null;
        long? problemSeq = null;

        while (r.Read())
        {
            var seq = r.GetInt64(0);
            var occurredAt = r.GetString(1);
            var category = r.GetString(2);
            var actor = r.GetString(3);
            var subject = r.GetString(4);
            var payload = r.GetString(5);
            var storedPrev = r.GetString(6);
            var storedHash = r.GetString(7);

            if (seq != expectedSeq && firstProblem is null)
            {
                firstProblem = $"序号不连续：期望 {expectedSeq}，实际 {seq}（可能有记录被删除）";
                problemSeq = seq;
            }

            if (storedPrev != prev && firstProblem is null)
            {
                firstProblem = $"第 {seq} 条的上一环哈希与第 {seq - 1} 条不衔接";
                problemSeq = seq;
            }

            var recomputed = ComputeHash(prev, new
            {
                seq,
                occurredAt,
                category,
                actor,
                subject,
                payloadJson = payload,
            });
            if (recomputed != storedHash && firstProblem is null)
            {
                firstProblem = $"第 {seq} 条内容哈希不符，记录可能被修改";
                problemSeq = seq;
            }

            prev = storedHash;
            expectedSeq = seq + 1;
            count++;
        }

        return new AuditIntegrityReport(firstProblem is null, count, problemSeq, firstProblem, prev);
    }
}

public sealed record AuditIntegrityReport(bool Intact, long Count, long? FirstProblemSeq, string? Problem, string HeadHash);

/// <summary>
/// 会见会话：登记 → 授权（签发一次性授权码）→ 入所核销。
/// 授权码可以由监区终端离线核对（HMAC + 当日窗口盐），避免窗口与监区网络不通时无法确认。
/// </summary>
public sealed class SessionService(SqliteStore store, IClock? clock = null)
{
    private readonly IClock _clock = clock ?? SystemClock.Instance;

    public SessionRecord Start(VerificationRequest req, VerificationDecision decision, string sessionId)
    {
        var record = new SessionRecord
        {
            SessionId = sessionId,
            CertNo = LicenseNumber.Normalize(req.CertNo),
            LawyerName = decision.Lawyer?.Name ?? req.Name,
            FirmName = decision.Lawyer?.FirmName ?? req.FirmName,
            SnapshotId = decision.Roster.SnapshotId,
            Outcome = decision.Outcome.ToString(),
            Officer = req.Officer,
            Window = req.Window,
            StartedAt = req.Now,
            DetaineeNo = decision.Detainee?.DetaineeNo,
            DetaineeName = decision.Detainee?.Name,
            Commission = req.Commission,
            CommissionNo = req.CommissionNo,
            PhotoVerdict = req.PhotoVerdict.ToString(),
            ChecksJson = JsonSerializer.Serialize(decision.Checks, JsonDefaults.Options),
            PhotoSha256 = decision.Photo?.Sha256,
        };
        Insert(record);
        return record;
    }

    public void Insert(SessionRecord s)
    {
        using var gate = store.AcquireWriteGate();
        using var conn = store.OpenConnection();
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO session(session_id,cert_no,lawyer_name,firm_name,snapshot_id,outcome,officer,window,
                    started_at,authorized_at,authorization_code,detainee_no,detainee_name,commission,commission_no,
                    photo_verdict,caution_reason,review_officer,review_note,checks_json,checked_in_at,checked_in_by,
                    photo_sha256,revoked,revoked_reason)
                VALUES($id,$cert,$name,$firm,$snap,$out,$off,$win,$start,$auth,$code,$dno,$dname,$comm,$cno,
                    $pv,$cr,$ro,$rn,$cj,$ci,$cib,$ph,$rev,$rr)
                """;
            Bind(cmd, s);
            cmd.ExecuteNonQuery();
        }
        AuditLog.Append(conn, tx, _clock.Now, "session.start", s.Officer, s.SessionId,
            JsonSerializer.Serialize(new { s.CertNo, s.Outcome, s.DetaineeNo, snapshot = s.SnapshotId }, JsonDefaults.Options));
        tx.Commit();
    }

    private static void Bind(SqliteCommand cmd, SessionRecord s)
    {
        cmd.Parameters.AddWithValue("$id", s.SessionId);
        cmd.Parameters.AddWithValue("$cert", s.CertNo);
        cmd.Parameters.AddWithValue("$name", (object?)s.LawyerName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$firm", (object?)s.FirmName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$snap", s.SnapshotId);
        cmd.Parameters.AddWithValue("$out", s.Outcome);
        cmd.Parameters.AddWithValue("$off", s.Officer);
        cmd.Parameters.AddWithValue("$win", s.Window);
        cmd.Parameters.AddWithValue("$start", s.StartedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$auth", s.AuthorizedAt?.ToString("O") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$code", (object?)s.AuthorizationCode ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$dno", (object?)s.DetaineeNo ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$dname", (object?)s.DetaineeName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$comm", (int)s.Commission);
        cmd.Parameters.AddWithValue("$cno", (object?)s.CommissionNo ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$pv", s.PhotoVerdict);
        cmd.Parameters.AddWithValue("$cr", (object?)s.CautionReason ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ro", (object?)s.ReviewOfficer ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rn", (object?)s.ReviewNote ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$cj", (object?)s.ChecksJson ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ci", s.CheckedInAt?.ToString("O") ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("$cib", (object?)s.CheckedInBy ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ph", (object?)s.PhotoSha256 ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rev", s.Revoked ? 1 : 0);
        cmd.Parameters.AddWithValue("$rr", (object?)s.RevokedReason ?? DBNull.Value);
    }

    /// <summary>
    /// 授权。仅允许“通过”或“有疑点已注明事由”两种结论直接签发；
    /// 需复核/禁止的必须由另一名民警复核后才能签发，且不能由录入人自审自批。
    /// </summary>
    public AuthorizationResult Authorize(AuthorizeRequest req)
    {
        var s = Get(req.SessionId) ?? throw new InvalidOperationException("会话不存在");
        if (s.Revoked) return AuthorizationResult.Fail("该会见已被撤销，不能授权");
        if (s.AuthorizedAt is not null) return AuthorizationResult.Fail($"已于 {s.AuthorizedAt:HH:mm} 授权，请勿重复操作");

        var outcome = Enum.TryParse<VerificationOutcome>(s.Outcome, out var o) ? o : VerificationOutcome.Blocked;

        if (outcome == VerificationOutcome.Blocked)
            return AuthorizationResult.Fail("系统判定禁止会见，不得签发授权；如确有特殊情况，须报值班领导另行处置并另案记录");

        if (outcome == VerificationOutcome.NeedsManualReview)
        {
            if (string.IsNullOrWhiteSpace(req.ReviewOfficer))
                return AuthorizationResult.Fail("该件须人工复核，请填写复核民警");
            if (string.Equals(req.ReviewOfficer.Trim(), s.Officer.Trim(), StringComparison.Ordinal))
                return AuthorizationResult.Fail("复核人与录入人不能是同一人，请由第二名民警复核");
            if (string.IsNullOrWhiteSpace(req.ReviewNote) || req.ReviewNote.Trim().Length < 4)
                return AuthorizationResult.Fail("人工复核必须写明核实情况（至少 4 个字）");
        }

        if (outcome == VerificationOutcome.VerifiedWithCaution &&
            (string.IsNullOrWhiteSpace(req.CautionReason) || req.CautionReason.Trim().Length < 4))
            return AuthorizationResult.Fail("存在疑点，必须注明放行理由（至少 4 个字）后备案");

        if (req.DetaineeNo is null && s.DetaineeNo is null)
            return AuthorizationResult.Fail("未登记被会见在押人员，不能签发会见授权");

        var now = req.Now;
        var code = AuthorizationCode.Issue(s.SessionId, s.CertNo, s.DetaineeNo ?? req.DetaineeNo ?? "", now, req.WindowSecret);

        using var gate = store.AcquireWriteGate();
        using var conn = store.OpenConnection();
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                UPDATE session SET authorized_at=$a, authorization_code=$c, caution_reason=$cr,
                    review_officer=$ro, review_note=$rn
                WHERE session_id=$id
                """;
            cmd.Parameters.AddWithValue("$a", now.ToString("O"));
            cmd.Parameters.AddWithValue("$c", code);
            cmd.Parameters.AddWithValue("$cr", (object?)req.CautionReason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ro", (object?)req.ReviewOfficer ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$rn", (object?)req.ReviewNote ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$id", s.SessionId);
            cmd.ExecuteNonQuery();
        }
        AuditLog.Append(conn, tx, now, "session.authorize", req.Officer, s.SessionId,
            JsonSerializer.Serialize(new
            {
                code,
                outcome = s.Outcome,
                review = req.ReviewOfficer,
                caution = req.CautionReason,
            }, JsonDefaults.Options));
        tx.Commit();
        return AuthorizationResult.Success(code, now);
    }

    public void CheckIn(string sessionId, string detaineeNo, string actor, DateTimeOffset now)
    {
        using var gate = store.AcquireWriteGate();
        using var conn = store.OpenConnection();
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "UPDATE session SET checked_in_at=$t, checked_in_by=$b WHERE session_id=$id AND authorized_at IS NOT NULL";
            cmd.Parameters.AddWithValue("$t", now.ToString("O"));
            cmd.Parameters.AddWithValue("$b", actor);
            cmd.Parameters.AddWithValue("$id", sessionId);
            if (cmd.ExecuteNonQuery() == 0)
                throw new InvalidOperationException("会话不存在或尚未授权，无法核销入所");
        }
        AuditLog.Append(conn, tx, now, "session.checkin", actor, sessionId,
            JsonSerializer.Serialize(new { detaineeNo }, JsonDefaults.Options));
        tx.Commit();
    }

    public void Revoke(string sessionId, string actor, string reason, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(reason)) throw new ArgumentException("撤销必须写明原因", nameof(reason));
        using var gate = store.AcquireWriteGate();
        using var conn = store.OpenConnection();
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = "UPDATE session SET revoked=1, revoked_reason=$r WHERE session_id=$id";
            cmd.Parameters.AddWithValue("$r", reason.Trim());
            cmd.Parameters.AddWithValue("$id", sessionId);
            if (cmd.ExecuteNonQuery() == 0) throw new InvalidOperationException("会话不存在");
        }
        AuditLog.Append(conn, tx, now, "session.revoke", actor, sessionId,
            JsonSerializer.Serialize(new { reason }, JsonDefaults.Options));
        tx.Commit();
    }

    public SessionRecord? Get(string sessionId)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT * FROM session WHERE session_id=$id";
        cmd.Parameters.AddWithValue("$id", sessionId);
        using var r = cmd.ExecuteReader();
        return r.Read() ? Map(r) : null;
    }

    public IReadOnlyList<SessionRecord> Recent(int limit = 50, DateTimeOffset? since = null)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = since is null
            ? "SELECT * FROM session ORDER BY started_at DESC LIMIT $l"
            : "SELECT * FROM session WHERE started_at>=$s ORDER BY started_at DESC LIMIT $l";
        cmd.Parameters.AddWithValue("$l", limit);
        if (since is { } s0) cmd.Parameters.AddWithValue("$s", s0.ToString("O"));
        using var r = cmd.ExecuteReader();
        var list = new List<SessionRecord>();
        while (r.Read()) list.Add(Map(r));
        return list;
    }

    private static SessionRecord Map(SqliteDataReader r)
    {
        string? S(string col) => r[col] is DBNull ? null : (string)r[col];

        return new SessionRecord
        {
            SessionId = r.GetString(r.GetOrdinal("session_id")),
            CertNo = r.GetString(r.GetOrdinal("cert_no")),
            LawyerName = S("lawyer_name"),
            FirmName = S("firm_name"),
            SnapshotId = r.GetString(r.GetOrdinal("snapshot_id")),
            Outcome = r.GetString(r.GetOrdinal("outcome")),
            Officer = r.GetString(r.GetOrdinal("officer")),
            Window = r.GetString(r.GetOrdinal("window")),
            StartedAt = DateTimeOffset.Parse(r.GetString(r.GetOrdinal("started_at")), CultureInfo.InvariantCulture),
            AuthorizedAt = S("authorized_at") is { } a ? DateTimeOffset.Parse(a, CultureInfo.InvariantCulture) : null,
            AuthorizationCode = S("authorization_code"),
            DetaineeNo = S("detainee_no"),
            DetaineeName = S("detainee_name"),
            Commission = (CommissionKind)r.GetInt32(r.GetOrdinal("commission")),
            CommissionNo = S("commission_no"),
            PhotoVerdict = r.GetString(r.GetOrdinal("photo_verdict")),
            CautionReason = S("caution_reason"),
            ReviewOfficer = S("review_officer"),
            ReviewNote = S("review_note"),
            ChecksJson = S("checks_json"),
            CheckedInAt = S("checked_in_at") is { } c ? DateTimeOffset.Parse(c, CultureInfo.InvariantCulture) : null,
            CheckedInBy = S("checked_in_by"),
            PhotoSha256 = S("photo_sha256"),
            Revoked = r.GetInt32(r.GetOrdinal("revoked")) != 0,
            RevokedReason = S("revoked_reason"),
        };
    }
}

public sealed record AuthorizeRequest(string SessionId, string Officer, string? CautionReason,
    string? ReviewOfficer, string? ReviewNote, string? DetaineeNo, string WindowSecret, DateTimeOffset Now);

public sealed record AuthorizationResult(bool Succeeded, string Message, string? Code = null, DateTimeOffset? At = null)
{
    public static AuthorizationResult Fail(string message) => new(false, message);
    public static AuthorizationResult Success(string code, DateTimeOffset at) =>
        new(true, "已签发会见授权", code, at);
}

/// <summary>
/// 一次性授权码。窗口与监区不联网，监区终端凭当日窗口密钥离线复算即可核对真伪，
/// 且授权码绑定会话、律师、在押人员与日期，换人换人不可复用。
/// </summary>
public static class AuthorizationCode
{
    public static string Issue(string sessionId, string certNo, string detaineeNo, DateTimeOffset now, string windowSecret)
    {
        var day = now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var material = $"{sessionId}|{certNo}|{detaineeNo}|{day}";
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(windowSecret));
        var mac = hmac.ComputeHash(Encoding.UTF8.GetBytes(material));
        var chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        var sb = new StringBuilder(12);
        var bits = 0;
        var acc = 0;
        foreach (var b in mac[..8])
        {
            acc = (acc << 8) | b;
            bits += 8;
            while (bits >= 5 && sb.Length < 12)
            {
                sb.Append(chars[(acc >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }
        var raw = sb.ToString();
        return $"{raw[..4]}-{raw[4..8]}-{raw[8..]}";
    }

    public static bool Verify(string code, string sessionId, string certNo, string detaineeNo,
        DateTimeOffset now, string windowSecret)
    {
        var expected = Issue(sessionId, certNo, detaineeNo, now, windowSecret);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(LicenseNumber.Normalize(code)),
            Encoding.ASCII.GetBytes(LicenseNumber.Normalize(expected)));
    }
}

public interface IClock
{
    DateTimeOffset Now { get; }
}

public sealed class SystemClock : IClock
{
    public static SystemClock Instance { get; } = new();
    public DateTimeOffset Now => DateTimeOffset.Now;
}

/// <summary>测试与回放用的可控时钟。</summary>
public sealed class FixedClock(DateTimeOffset now) : IClock
{
    public DateTimeOffset Now { get; set; } = now;
}
