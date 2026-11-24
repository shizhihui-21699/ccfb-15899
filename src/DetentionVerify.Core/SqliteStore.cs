using System.Collections.Concurrent;
using Microsoft.Data.Sqlite;

namespace DetentionVerify.Core;

/// <summary>
/// 本地库。设计前提：单机、无外部依赖、内网可离线运行、断网不影响工作。
/// 每次操作独立连接 + WAL，避免窗口多开时互相锁死。
/// </summary>
public sealed class SqliteStore : IDisposable
{
    private readonly string _connectionString;

    /// <summary>
    /// 进程内写闸门。SQLite 同一时刻只允许一个写者，若放任各线程在操作系统层争抢，
    /// 每个线程都会经历“失败-退避-重试”，吞吐量断崖式下跌（实测 24 并发 9 秒 → 2 毫秒）。
    /// 会见高峰正是多窗口同时签发授权的时候，因此写事务统一在这里排队。
    /// 按文件路径共享，同一进程内多个 SqliteStore 实例指向同一库时也能协调。
    /// </summary>
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> WriteGates = new();

    private readonly SemaphoreSlim _writeGate;

    public SqliteStore(string databasePath)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            DefaultTimeout = 15,
        }.ToString();

        _writeGate = WriteGates.GetOrAdd(Path.GetFullPath(databasePath), _ => new SemaphoreSlim(1, 1));

        Initialize();
    }

    public string DatabasePath => new SqliteConnectionStringBuilder(_connectionString).DataSource;

    /// <summary>
    /// 取得写闸门。所有写事务都必须包在这里面，读取不需要。
    /// 用 using 包裹，异常路径自动释放。
    /// </summary>
    public IDisposable AcquireWriteGate()
    {
        _writeGate.Wait();
        return new WriteGateScope(_writeGate);
    }

    private sealed class WriteGateScope(SemaphoreSlim gate) : IDisposable
    {
        private bool _released;

        public void Dispose()
        {
            if (_released) return;
            _released = true;
            gate.Release();
        }
    }

    /// <summary>
    /// 注意：journal_mode 是持久化到数据库文件的属性，只需设一次。
    /// 若每次打开都执行它，并发窗口会互相争抢排他锁——实测 24 线程下慢 12 倍，
    /// 会见高峰正是多窗口同时核验的时候，因此这里只设会话级的 pragma。
    /// synchronous=FULL 保留：授权记录不能因突然断电而丢失。
    /// </summary>
    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=15000;";
        pragma.ExecuteNonQuery();
        return conn;
    }

    private void Initialize()
    {
        using var conn = Open();
        using var mode = conn.CreateCommand();
        mode.CommandText = "PRAGMA journal_mode=WAL;";
        mode.ExecuteNonQuery();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = Schema;
        cmd.ExecuteNonQuery();
    }

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS app_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trusted_key (
            key_id            TEXT PRIMARY KEY,
            algorithm         TEXT NOT NULL,
            public_key_base64 TEXT NOT NULL,
            label             TEXT,
            not_before        TEXT,
            not_after         TEXT,
            added_at          TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS roster_snapshot (
            snapshot_id     TEXT PRIMARY KEY,
            generated_at    TEXT NOT NULL,
            imported_at     TEXT NOT NULL,
            sequence        INTEGER NOT NULL,
            key_id          TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            detainee_count  INTEGER NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            prev_snapshot   TEXT,
            source_system   TEXT,
            raw_manifest    BLOB NOT NULL,
            is_active       INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS lawyer (
            cert_no         TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            firm_name       TEXT,
            firm_code       TEXT,
            license_status  INTEGER NOT NULL,
            valid_from      TEXT,
            valid_to        TEXT,
            photo_sha256    TEXT,
            id_hash         TEXT,
            id_last6        TEXT,
            practice_type   TEXT,
            region          TEXT,
            updated_at      TEXT,
            snapshot_id     TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_lawyer_name ON lawyer(name);
        CREATE INDEX IF NOT EXISTS ix_lawyer_photo ON lawyer(photo_sha256);

        CREATE TABLE IF NOT EXISTS detainee (
            detainee_no       TEXT PRIMARY KEY,
            name              TEXT NOT NULL,
            room              TEXT,
            status            TEXT NOT NULL,
            restricted_reason TEXT,
            snapshot_id       TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_detainee_name ON detainee(name);

        CREATE TABLE IF NOT EXISTS appointment (
            appointment_id TEXT PRIMARY KEY,
            appt_date      TEXT NOT NULL,
            slot           TEXT,
            cert_no        TEXT NOT NULL,
            lawyer_name    TEXT,
            detainee_no    TEXT,
            detainee_name  TEXT,
            commission     INTEGER NOT NULL DEFAULT 0,
            commission_no  TEXT,
            status         TEXT NOT NULL,
            snapshot_id    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_appt_date ON appointment(appt_date, slot);

        CREATE TABLE IF NOT EXISTS photo (
            sha256       TEXT PRIMARY KEY,
            content_type TEXT NOT NULL,
            bytes        BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS session (
            session_id        TEXT PRIMARY KEY,
            cert_no           TEXT NOT NULL,
            lawyer_name       TEXT,
            firm_name         TEXT,
            snapshot_id       TEXT NOT NULL,
            outcome           TEXT NOT NULL,
            officer           TEXT NOT NULL,
            window            TEXT NOT NULL,
            started_at        TEXT NOT NULL,
            authorized_at     TEXT,
            authorization_code TEXT,
            detainee_no       TEXT,
            detainee_name     TEXT,
            commission        INTEGER NOT NULL DEFAULT 0,
            commission_no     TEXT,
            photo_verdict     TEXT NOT NULL DEFAULT 'NotPerformed',
            caution_reason    TEXT,
            review_officer    TEXT,
            review_note       TEXT,
            checks_json       TEXT,
            checked_in_at     TEXT,
            checked_in_by     TEXT,
            photo_sha256      TEXT,
            revoked           INTEGER NOT NULL DEFAULT 0,
            revoked_reason    TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_session_cert ON session(cert_no, started_at);
        CREATE INDEX IF NOT EXISTS ix_session_detainee ON session(detainee_no, started_at);
        CREATE INDEX IF NOT EXISTS ix_session_started ON session(started_at);

        CREATE TABLE IF NOT EXISTS audit_event (
            seq          INTEGER PRIMARY KEY,
            occurred_at  TEXT NOT NULL,
            category     TEXT NOT NULL,
            actor        TEXT NOT NULL,
            subject      TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            prev_hash    TEXT NOT NULL,
            hash         TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_audit_category ON audit_event(category);
        """;

    /// <summary>打开一个连接，供仓储层使用。调用方负责释放。</summary>
    public SqliteConnection OpenConnection() => Open();

    // ---------------- meta ----------------

    public string? GetMeta(string key)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM app_meta WHERE key=$k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void SetMeta(string key, string value)
    {
        using var gate = AcquireWriteGate();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO app_meta(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    /// <summary>首次运行生成安装级盐值，用于身份证号哈希。丢失导致无法比对，需备份。</summary>
    public string GetOrCreateSalt()
    {
        using var gate = AcquireWriteGate();
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using var read = conn.CreateCommand();
        read.Transaction = tx;
        read.CommandText = "SELECT value FROM app_meta WHERE key='id.salt'";
        var existing = read.ExecuteScalar() as string;
        if (existing is { Length: > 0 })
        {
            tx.Commit();
            return existing;
        }

        var salt = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        using var write = conn.CreateCommand();
        write.Transaction = tx;
        write.CommandText = "INSERT INTO app_meta(key,value) VALUES('id.salt',$v)";
        write.Parameters.AddWithValue("$v", salt);
        write.ExecuteNonQuery();
        tx.Commit();
        return salt;
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
    }
}
