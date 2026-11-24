using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace DetentionVerify.Core;

public sealed record ImportResult(bool Ok, string Message, string? SnapshotId = null,
    int RecordCount = 0, int DetaineeCount = 0, IReadOnlyList<string>? Warnings = null,
    IReadOnlyList<string>? Errors = null)
{
    public static ImportResult Fail(params string[] errors) => new(false, errors.FirstOrDefault() ?? "导入失败", Errors: errors);
}

public sealed record ImportOptions(string PackageDirectory, string Actor, DateTimeOffset Now,
    bool AcceptStaleSequence = false);

/// <summary>
/// 导入流程：校验签名 → 校验清单哈希 → 校验批次单调性 → 单事务替换生效名册。
/// 任何一步失败都完整回滚，旧名册保持可用——绝对不允许“导入到一半，窗口查不到人”。
/// </summary>
public sealed class RosterImporter(SqliteStore store)
{
    public ImportResult Import(ImportOptions options)
    {
        var dir = Path.GetFullPath(options.PackageDirectory);
        var errors = new List<string>();
        var warnings = new List<string>();

        if (!Directory.Exists(dir)) return ImportResult.Fail($"导入目录不存在：{dir}");

        var manifestPath = Path.Combine(dir, "manifest.json");
        var sigPath = Path.Combine(dir, "manifest.sig");
        if (!File.Exists(manifestPath)) return ImportResult.Fail("缺少 manifest.json");
        if (!File.Exists(sigPath)) return ImportResult.Fail("缺少 manifest.sig");

        var manifestBytes = File.ReadAllBytes(manifestPath);
        var signature = File.ReadAllBytes(sigPath);

        RosterManifest? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<RosterManifest>(manifestBytes, JsonDefaults.Options);
        }
        catch (JsonException ex)
        {
            return ImportResult.Fail($"manifest.json 解析失败：{ex.Message}");
        }
        if (manifest is null) return ImportResult.Fail("manifest.json 为空");
        if (manifest.Format != "detention-roster/v1")
            return ImportResult.Fail($"不支持的清单格式：{manifest.Format}");

        var key = TrustedKeyRepository.Get(store, manifest.KeyId);
        if (key is null)
            return ImportResult.Fail($"清单签名密钥 {manifest.KeyId} 不在本机信任列表中，拒绝导入");

        if (!PackageSignature.Verify(key, manifestBytes, signature))
            return ImportResult.Fail("签名校验失败：包体与签名不符，或公钥不匹配");

        if (key.NotAfter is { } notAfter && options.Now > notAfter)
            return ImportResult.Fail($"签名密钥已于 {notAfter:yyyy-MM-dd} 过期，请联系省级平台换发");

        var recordsPath = Path.Combine(dir, "records.jsonl");
        if (!File.Exists(recordsPath))
        {
            recordsPath = Path.Combine(dir, "records.json");
            if (!File.Exists(recordsPath)) return ImportResult.Fail("缺少 records.jsonl");
        }
        if (!File.Exists(Path.Combine(dir, "detainees.json")))
            return ImportResult.Fail("缺少 detainees.json");

        if (!string.Equals(PackageSignature.HashFile(recordsPath), manifest.RecordsSha256, StringComparison.OrdinalIgnoreCase))
            return ImportResult.Fail("律师名册哈希与清单不符，文件可能被篡改或复制不完整");
        if (!string.Equals(PackageSignature.HashFile(Path.Combine(dir, "detainees.json")), manifest.DetaineesSha256,
                StringComparison.OrdinalIgnoreCase))
            return ImportResult.Fail("在押人员名册哈希与清单不符");

        var lawyers = new List<LawyerRecord>();
        var detainees = new List<DetaineeRecord>();
        var appointments = new List<AppointmentRecord>();
        var apptPath = Path.Combine(dir, "appointments.json");
        if (manifest.AppointmentsSha256 is { Length: > 0 })
        {
            if (!File.Exists(apptPath)) return ImportResult.Fail("清单声明包含预约名单，但缺少 appointments.json");
            if (!string.Equals(PackageSignature.HashFile(apptPath), manifest.AppointmentsSha256,
                    StringComparison.OrdinalIgnoreCase))
                return ImportResult.Fail("预约名单哈希与清单不符");
        }

        try
        {
            foreach (var rec in ReadRecords(recordsPath)) lawyers.Add(rec);
            foreach (var det in ReadDetainees(Path.Combine(dir, "detainees.json"))) detainees.Add(det);
            if (File.Exists(apptPath))
            {
                var appts = JsonSerializer.Deserialize<List<AppointmentRecord>>(File.ReadAllText(apptPath), JsonDefaults.Options);
                appointments.AddRange(appts ?? []);
            }
        }
        catch (JsonException ex)
        {
            return ImportResult.Fail($"名册内容解析失败：{ex.Message}");
        }

        if (lawyers.Count != manifest.RecordCount)
            errors.Add($"清单声明 {manifest.RecordCount} 条律师记录，实际 {lawyers.Count} 条");
        if (detainees.Count != manifest.DetaineeCount)
            errors.Add($"清单声明 {manifest.DetaineeCount} 条在押记录，实际 {detainees.Count} 条");
        if (errors.Count > 0) return ImportResult.Fail([.. errors]);

        // 证号重复说明上游数据有问题，静默去重会让“谁是真的”变成猜测，必须显式失败。
        var dupCerts = lawyers.GroupBy(l => LicenseNumber.Normalize(l.CertNo))
            .Where(g => g.Count() > 1).Select(g => g.Key).Take(5).ToList();
        if (dupCerts.Count > 0)
            return ImportResult.Fail($"名册内存在重复证号：{string.Join(", ", dupCerts)}");
        var dupDetainees = detainees.GroupBy(d => d.DetaineeNo).Where(g => g.Count() > 1)
            .Select(g => g.Key).Take(5).ToList();
        if (dupDetainees.Count > 0)
            return ImportResult.Fail($"在押名册内存在重复编号：{string.Join(", ", dupDetainees)}");

        var active = RosterRepository.GetActiveStamp(store);
        if (active is { } cur)
        {
            if (manifest.Sequence < cur.Sequence && !options.AcceptStaleSequence)
                return ImportResult.Fail(
                    $"此包序号 {manifest.Sequence} 低于当前生效名册的序号 {cur.Sequence}，疑似误用旧包；如确需回滚请由管理员操作");
            if (manifest.Sequence == cur.Sequence && manifest.SnapshotId != cur.SnapshotId)
                return ImportResult.Fail($"已存在同序号 {manifest.Sequence} 的不同快照，拒绝导入");
        }

        var photosDir = Path.Combine(dir, "photos");
        var photos = new Dictionary<string, (string ContentType, byte[] Bytes)>(StringComparer.OrdinalIgnoreCase);
        if (Directory.Exists(photosDir))
        {
            foreach (var file in Directory.EnumerateFiles(photosDir))
            {
                var bytes = File.ReadAllBytes(file);
                var sha = PackageSignature.ComputeSha256Hex(bytes);
                var name = Path.GetFileNameWithoutExtension(file);
                if (!string.Equals(name, sha, StringComparison.OrdinalIgnoreCase))
                    warnings.Add($"照片文件名 {Path.GetFileName(file)} 与其内容哈希不一致，已按内容哈希存库");
                photos[sha] = (GuessContentType(file), bytes);
            }
        }

        var missingPhotos = lawyers.Count(l => !string.IsNullOrEmpty(l.PhotoSha256) && !photos.ContainsKey(l.PhotoSha256));
        if (missingPhotos > 0)
            warnings.Add($"{missingPhotos} 名律师的照片未随包提供，窗口将显示“无照片”，需以实体证核对");

        var salt = store.GetOrCreateSalt();

        using var gate = store.AcquireWriteGate();
        using var conn = store.OpenConnection();
        using var tx = conn.BeginTransaction();

        try
        {
            using (var del = conn.CreateCommand())
            {
                del.Transaction = tx;
                del.CommandText = "DELETE FROM photo; DELETE FROM lawyer; DELETE FROM detainee; DELETE FROM appointment;";
                del.ExecuteNonQuery();
            }

            using (var photoCmd = conn.CreateCommand())
            {
                photoCmd.Transaction = tx;
                photoCmd.CommandText = "INSERT OR REPLACE INTO photo(sha256,content_type,bytes) VALUES($s,$c,$b)";
                var ps = photoCmd.Parameters.Add("$s", SqliteType.Text);
                var pc = photoCmd.Parameters.Add("$c", SqliteType.Text);
                var pb = photoCmd.Parameters.Add("$b", SqliteType.Blob);
                foreach (var (sha, p) in photos)
                {
                    ps.Value = sha;
                    pc.Value = p.ContentType;
                    pb.Value = p.Bytes;
                    photoCmd.ExecuteNonQuery();
                }
            }

            using (var lc = conn.CreateCommand())
            {
                lc.Transaction = tx;
                lc.CommandText = """
                    INSERT INTO lawyer(cert_no,name,firm_name,firm_code,license_status,valid_from,valid_to,
                        photo_sha256,id_hash,id_last6,practice_type,region,updated_at,snapshot_id)
                    VALUES($cert,$name,$firm,$firmcode,$status,$vfrom,$vto,$photo,$idhash,$idlast6,$ptype,$region,$upd,$snap)
                    """;
                var pCert = lc.Parameters.Add("$cert", SqliteType.Text);
                var pName = lc.Parameters.Add("$name", SqliteType.Text);
                var pFirm = lc.Parameters.Add("$firm", SqliteType.Text);
                var pFirmCode = lc.Parameters.Add("$firmcode", SqliteType.Text);
                var pStatus = lc.Parameters.Add("$status", SqliteType.Integer);
                var pVFrom = lc.Parameters.Add("$vfrom", SqliteType.Text);
                var pVTo = lc.Parameters.Add("$vto", SqliteType.Text);
                var pPhoto = lc.Parameters.Add("$photo", SqliteType.Text);
                var pIdHash = lc.Parameters.Add("$idhash", SqliteType.Text);
                var pIdLast6 = lc.Parameters.Add("$idlast6", SqliteType.Text);
                var pPType = lc.Parameters.Add("$ptype", SqliteType.Text);
                var pRegion = lc.Parameters.Add("$region", SqliteType.Text);
                var pUpd = lc.Parameters.Add("$upd", SqliteType.Text);
                var pSnap = lc.Parameters.Add("$snap", SqliteType.Text);

                foreach (var l in lawyers)
                {
                    pCert.Value = LicenseNumber.Normalize(l.CertNo);
                    pName.Value = LicenseNumber.NormalizeName(l.Name);
                    pFirm.Value = (object?)l.FirmName ?? DBNull.Value;
                    pFirmCode.Value = (object?)l.FirmCode ?? DBNull.Value;
                    pStatus.Value = (int)l.LicenseStatus;
                    pVFrom.Value = l.ValidFrom?.ToString("yyyy-MM-dd") ?? (object)DBNull.Value;
                    pVTo.Value = l.ValidTo?.ToString("yyyy-MM-dd") ?? (object)DBNull.Value;
                    pPhoto.Value = (object?)l.PhotoSha256?.ToLowerInvariant() ?? DBNull.Value;
                    pIdHash.Value = string.IsNullOrWhiteSpace(l.IdNumber)
                        ? DBNull.Value : IdHashing.Hash(l.IdNumber, salt);
                    pIdLast6.Value = string.IsNullOrWhiteSpace(l.IdNumber)
                        ? DBNull.Value : IdHashing.Last6(l.IdNumber);
                    pPType.Value = (object?)l.PracticeType ?? DBNull.Value;
                    pRegion.Value = (object?)l.Region ?? DBNull.Value;
                    pUpd.Value = l.UpdatedAt?.ToString("O") ?? (object)DBNull.Value;
                    pSnap.Value = manifest.SnapshotId;
                    lc.ExecuteNonQuery();
                }
            }

            using (var dc = conn.CreateCommand())
            {
                dc.Transaction = tx;
                dc.CommandText = "INSERT INTO detainee(detainee_no,name,room,status,restricted_reason,snapshot_id) VALUES($no,$name,$room,$st,$rr,$snap)";
                var pNo = dc.Parameters.Add("$no", SqliteType.Text);
                var pName = dc.Parameters.Add("$name", SqliteType.Text);
                var pRoom = dc.Parameters.Add("$room", SqliteType.Text);
                var pSt = dc.Parameters.Add("$st", SqliteType.Text);
                var pRr = dc.Parameters.Add("$rr", SqliteType.Text);
                var pSnap = dc.Parameters.Add("$snap", SqliteType.Text);
                foreach (var d in detainees)
                {
                    pNo.Value = d.DetaineeNo;
                    pName.Value = d.Name;
                    pRoom.Value = (object?)d.Room ?? DBNull.Value;
                    pSt.Value = d.Status;
                    pRr.Value = (object?)d.RestrictedReason ?? DBNull.Value;
                    pSnap.Value = manifest.SnapshotId;
                    dc.ExecuteNonQuery();
                }
            }

            using (var ac = conn.CreateCommand())
            {
                ac.Transaction = tx;
                ac.CommandText = """
                    INSERT INTO appointment(appointment_id,appt_date,slot,cert_no,lawyer_name,detainee_no,detainee_name,
                        commission,commission_no,status,snapshot_id)
                    VALUES($id,$d,$slot,$cert,$name,$dno,$dname,$comm,$cno,$st,$snap)
                    """;
                var pId = ac.Parameters.Add("$id", SqliteType.Text);
                var pD = ac.Parameters.Add("$d", SqliteType.Text);
                var pSlot = ac.Parameters.Add("$slot", SqliteType.Text);
                var pCert = ac.Parameters.Add("$cert", SqliteType.Text);
                var pName = ac.Parameters.Add("$name", SqliteType.Text);
                var pDno = ac.Parameters.Add("$dno", SqliteType.Text);
                var pDname = ac.Parameters.Add("$dname", SqliteType.Text);
                var pComm = ac.Parameters.Add("$comm", SqliteType.Integer);
                var pCno = ac.Parameters.Add("$cno", SqliteType.Text);
                var pSt = ac.Parameters.Add("$st", SqliteType.Text);
                var pSnap = ac.Parameters.Add("$snap", SqliteType.Text);
                foreach (var a in appointments)
                {
                    pId.Value = a.AppointmentId;
                    pD.Value = a.Date.ToString("yyyy-MM-dd");
                    pSlot.Value = (object?)a.Slot ?? DBNull.Value;
                    pCert.Value = LicenseNumber.Normalize(a.CertNo);
                    pName.Value = (object?)a.LawyerName ?? DBNull.Value;
                    pDno.Value = (object?)a.DetaineeNo ?? DBNull.Value;
                    pDname.Value = (object?)a.DetaineeName ?? DBNull.Value;
                    pComm.Value = (int)a.Commission;
                    pCno.Value = (object?)a.CommissionNo ?? DBNull.Value;
                    pSt.Value = a.Status;
                    pSnap.Value = manifest.SnapshotId;
                    ac.ExecuteNonQuery();
                }
            }

            using (var sc = conn.CreateCommand())
            {
                sc.Transaction = tx;
                sc.CommandText = """
                    INSERT INTO roster_snapshot(snapshot_id,generated_at,imported_at,sequence,key_id,record_count,
                        detainee_count,manifest_sha256,prev_snapshot,source_system,raw_manifest,is_active)
                    VALUES($id,$gen,$imp,$seq,$key,$rc,$dc,$sha,$prev,$src,$raw,1)
                    ON CONFLICT(snapshot_id) DO UPDATE SET imported_at=excluded.imported_at, is_active=1
                    """;
                sc.Parameters.AddWithValue("$id", manifest.SnapshotId);
                sc.Parameters.AddWithValue("$gen", manifest.GeneratedAt.ToString("O"));
                sc.Parameters.AddWithValue("$imp", options.Now.ToString("O"));
                sc.Parameters.AddWithValue("$seq", manifest.Sequence);
                sc.Parameters.AddWithValue("$key", manifest.KeyId);
                sc.Parameters.AddWithValue("$rc", lawyers.Count);
                sc.Parameters.AddWithValue("$dc", detainees.Count);
                sc.Parameters.AddWithValue("$sha", PackageSignature.ComputeSha256Hex(manifestBytes));
                sc.Parameters.AddWithValue("$prev", (object?)manifest.PrevSnapshotId ?? DBNull.Value);
                sc.Parameters.AddWithValue("$src", (object?)manifest.SourceSystem ?? DBNull.Value);
                sc.Parameters.AddWithValue("$raw", manifestBytes);
                sc.ExecuteNonQuery();
            }

            using (var act = conn.CreateCommand())
            {
                act.Transaction = tx;
                act.CommandText = "UPDATE roster_snapshot SET is_active=0 WHERE snapshot_id<>$id";
                act.Parameters.AddWithValue("$id", manifest.SnapshotId);
                act.ExecuteNonQuery();
            }

            AuditLog.Append(conn, tx, options.Now, "roster.import", options.Actor, manifest.SnapshotId,
                JsonSerializer.Serialize(new
                {
                    manifest.Sequence,
                    manifest.RecordCount,
                    manifest.DetaineeCount,
                    KeyId = manifest.KeyId,
                    ManifestSha256 = PackageSignature.ComputeSha256Hex(manifestBytes),
                    Warnings = warnings.Count,
                }, JsonDefaults.Options));

            tx.Commit();
        }
        catch (Exception ex) when (ex is SqliteException or IOException)
        {
            tx.Rollback();
            return ImportResult.Fail($"写入本地库失败，已保持原名册不变：{ex.Message}");
        }

        return new ImportResult(true,
            $"导入成功：{lawyers.Count} 名律师、{detainees.Count} 名在押人员{(appointments.Count > 0 ? $"、{appointments.Count} 条预约" : "")}，快照 {manifest.SnapshotId}",
            manifest.SnapshotId, lawyers.Count, detainees.Count, warnings);
    }

    private static IEnumerable<LawyerRecord> ReadRecords(string path)
    {
        if (path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var rec = JsonSerializer.Deserialize<LawyerRecord>(line, JsonDefaults.Options);
                if (rec is not null) yield return rec;
            }
            yield break;
        }

        var all = JsonSerializer.Deserialize<List<LawyerRecord>>(File.ReadAllText(path), JsonDefaults.Options);
        foreach (var rec in all ?? []) yield return rec;
    }

    private static IEnumerable<DetaineeRecord> ReadDetainees(string path)
    {
        var all = JsonSerializer.Deserialize<List<DetaineeRecord>>(File.ReadAllText(path), JsonDefaults.Options);
        foreach (var rec in all ?? []) yield return rec;
    }

    private static string GuessContentType(string file) => Path.GetExtension(file).ToLowerInvariant() switch
    {
        ".png" => "image/png",
        ".webp" => "image/webp",
        _ => "image/jpeg",
    };
}

public static class TrustedKeyRepository
{
    public static TrustedKey? Get(SqliteStore store, string keyId)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key_id,algorithm,public_key_base64,label,not_before,not_after FROM trusted_key WHERE key_id=$k";
        cmd.Parameters.AddWithValue("$k", keyId);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return null;
        return new TrustedKey(
            r.GetString(0), r.GetString(1), r.GetString(2),
            r.IsDBNull(3) ? null : r.GetString(3),
            r.IsDBNull(4) ? null : DateTimeOffset.Parse(r.GetString(4), CultureInfo.InvariantCulture),
            r.IsDBNull(5) ? null : DateTimeOffset.Parse(r.GetString(5), CultureInfo.InvariantCulture));
    }

    public static void Add(SqliteStore store, TrustedKey key, string actor, DateTimeOffset now)
    {
        using var gate = store.AcquireWriteGate();
        using var conn = store.OpenConnection();
        using var tx = conn.BeginTransaction();
        using (var cmd = conn.CreateCommand())
        {
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO trusted_key(key_id,algorithm,public_key_base64,label,not_before,not_after,added_at)
                VALUES($k,$a,$p,$l,$nb,$na,$at)
                ON CONFLICT(key_id) DO UPDATE SET algorithm=excluded.algorithm,public_key_base64=excluded.public_key_base64,
                    label=excluded.label,not_before=excluded.not_before,not_after=excluded.not_after
                """;
            cmd.Parameters.AddWithValue("$k", key.KeyId);
            cmd.Parameters.AddWithValue("$a", key.Algorithm);
            cmd.Parameters.AddWithValue("$p", key.PublicKeyBase64);
            cmd.Parameters.AddWithValue("$l", (object?)key.Label ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$nb", key.NotBefore?.ToString("O") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$na", key.NotAfter?.ToString("O") ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("$at", now.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        AuditLog.Append(conn, tx, now, "trustkey.add", actor, key.KeyId,
            JsonSerializer.Serialize(new { key.Algorithm, key.Label }, JsonDefaults.Options));
        tx.Commit();
    }

    public static IReadOnlyList<TrustedKey> List(SqliteStore store)
    {
        using var conn = store.OpenConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key_id,algorithm,public_key_base64,label,not_before,not_after FROM trusted_key ORDER BY added_at DESC";
        using var r = cmd.ExecuteReader();
        var list = new List<TrustedKey>();
        while (r.Read())
        {
            list.Add(new TrustedKey(r.GetString(0), r.GetString(1), r.GetString(2),
                r.IsDBNull(3) ? null : r.GetString(3),
                r.IsDBNull(4) ? null : DateTimeOffset.Parse(r.GetString(4), CultureInfo.InvariantCulture),
                r.IsDBNull(5) ? null : DateTimeOffset.Parse(r.GetString(5), CultureInfo.InvariantCulture)));
        }
        return list;
    }
}
