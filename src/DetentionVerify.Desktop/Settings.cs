using System.Text.Json;
using System.Text.Json.Serialization;

namespace DetentionVerify.Desktop;

/// <summary>
/// 本机设置。放在数据目录而非程序目录：程序目录常为只读安装位置，
/// 且重装程序时不应丢失窗口密钥（否则监区终端签发的授权码会全部失效）。
/// </summary>
public sealed class Settings
{
    [JsonPropertyName("windowName")]
    public string WindowName { get; set; } = "1号窗口";

    [JsonPropertyName("officerName")]
    public string OfficerName { get; set; } = "";

    [JsonPropertyName("windowSecret")]
    public string WindowSecret { get; set; } = "";

    [JsonPropertyName("rosterWarnHours")]
    public double RosterWarnHours { get; set; } = 30;

    [JsonPropertyName("rosterDegradeHours")]
    public double RosterDegradeHours { get; set; } = 96;

    /// <summary>超过此秒数仍未完成一次核验，界面上提示“录入过慢”，用于自查而非考核。</summary>
    [JsonPropertyName("slowCheckSeconds")]
    public int SlowCheckSeconds { get; set; } = 45;

    [JsonIgnore]
    public string DataDirectory { get; private set; } = "";

    public static string ResolveDataDirectory()
    {
        // 允许运维用环境变量指向受控目录（如加密盘），否则用用户本地应用数据。
        var overridden = Environment.GetEnvironmentVariable("DETENTION_VERIFY_DATA");
        if (!string.IsNullOrWhiteSpace(overridden)) return overridden;

        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(baseDir))
            baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        return Path.Combine(baseDir, "DetentionVerify");
    }

    public static Settings Load(string dataDir)
    {
        var path = Path.Combine(dataDir, "settings.json");
        Settings settings;
        if (File.Exists(path))
        {
            try
            {
                settings = JsonSerializer.Deserialize<Settings>(File.ReadAllText(path)) ?? new Settings();
            }
            catch (JsonException)
            {
                settings = new Settings();
            }
        }
        else
        {
            settings = new Settings();
        }

        settings.DataDirectory = dataDir;
        return settings;
    }

    public void Save(string? dataDir = null)
    {
        var dir = dataDir ?? DataDirectory;
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "settings.json");
        var tmp = path + ".tmp";

        // 权限收紧：含窗口密钥，不能让同机其他用户读到。
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(tmp, json);
        TryRestrict(tmp);
        File.Move(tmp, path, overwrite: true);
    }

    private static void TryRestrict(string path)
    {
        if (OperatingSystem.IsWindows()) return; // Windows 下依赖目录 ACL，不做额外处理
        try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
