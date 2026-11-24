using System.Globalization;

namespace DetentionVerify.Core;

/// <summary>
/// 当日预约名单。高峰时段窗口按名单点人名，避免逐个手打证号——这是削峰的主要手段。
/// 「已办」以是否已签发授权为准，而不是以是否查询过为准，避免误点“清空”后重复排队。
/// </summary>
public sealed class AppointmentRepository(SqliteStore store)
{
    public IReadOnlyList<AppointmentRow> ForDate(DateOnly date)
    {
        var dayStart = new DateTimeOffset(date.ToDateTime(TimeOnly.MinValue), TimeZoneInfo.Local.GetUtcOffset(DateTime.Now));
        var dayEnd = dayStart.AddDays(1);

        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT a.appointment_id, a.slot, a.cert_no, a.lawyer_name, a.detainee_no, a.detainee_name,
                   a.commission, a.commission_no, a.status,
                   (SELECT MAX(s.authorized_at) FROM session s
                     WHERE s.cert_no=a.cert_no AND IFNULL(s.detainee_no,'')=IFNULL(a.detainee_no,'')
                       AND s.authorized_at IS NOT NULL AND s.revoked=0
                       AND s.started_at>=$from AND s.started_at<$to) AS authorized_at,
                   (SELECT COUNT(*) FROM session s
                     WHERE s.cert_no=a.cert_no AND IFNULL(s.detainee_no,'')=IFNULL(a.detainee_no,'')
                       AND s.started_at>=$from AND s.started_at<$to) AS attempts
            FROM appointment a
            WHERE a.appt_date=$d AND a.status<>'已取消'
            ORDER BY a.slot, a.appointment_id
            """;
        cmd.Parameters.AddWithValue("$d", date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        cmd.Parameters.AddWithValue("$from", dayStart.ToString("O"));
        cmd.Parameters.AddWithValue("$to", dayEnd.ToString("O"));

        using var r = cmd.ExecuteReader();
        var list = new List<AppointmentRow>();
        while (r.Read())
        {
            list.Add(new AppointmentRow(
                r.GetString(0),
                r.IsDBNull(1) ? null : r.GetString(1),
                r.GetString(2),
                r.IsDBNull(3) ? null : r.GetString(3),
                r.IsDBNull(4) ? null : r.GetString(4),
                r.IsDBNull(5) ? null : r.GetString(5),
                (CommissionKind)r.GetInt32(6),
                r.IsDBNull(7) ? null : r.GetString(7),
                r.GetString(8),
                r.IsDBNull(9) ? null : DateTimeOffset.Parse(r.GetString(9), CultureInfo.InvariantCulture),
                r.GetInt32(10)));
        }
        return list;
    }

    /// <summary>高峰排队统计：当日预约总数、已办、待办。</summary>
    public QueueStats Stats(DateOnly date)
    {
        var rows = ForDate(date);
        var done = rows.Count(x => x.AuthorizedAt is not null);
        return new QueueStats(rows.Count, done, rows.Count - done);
    }
}

public sealed record AppointmentRow(
    string AppointmentId, string? Slot, string CertNo, string? LawyerName, string? DetaineeNo, string? DetaineeName,
    CommissionKind Commission, string? CommissionNo, string Status, DateTimeOffset? AuthorizedAt, int Attempts)
{
    public bool Done => AuthorizedAt is not null;

    public string DisplayName => LawyerName ?? CertNo;

    public string SlotText => string.IsNullOrWhiteSpace(Slot) ? "未排时段" : Slot;

    public string Subtitle
    {
        get
        {
            var detainee = DetaineeName ?? DetaineeNo ?? "未指定";
            var suffix = Done
                ? $"已办 {AuthorizedAt:HH:mm}"
                : Attempts > 0 ? $"已查询 {Attempts} 次未授权" : "待办";
            return $"会见 {detainee} · {suffix}";
        }
    }

    public string RowClass => Done ? "done" : Attempts > 0 ? "retry" : "pending";
}

public sealed record QueueStats(int Total, int Done, int Waiting);
