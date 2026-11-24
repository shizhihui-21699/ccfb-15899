using Avalonia;

namespace DetentionVerify.Desktop;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            // 窗口机器上没人看控制台，至少要落一份崩溃日志，便于排查。
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "DetentionVerify", "logs");
                Directory.CreateDirectory(dir);
                File.AppendAllText(Path.Combine(dir, "crash.log"),
                    $"[{DateTimeOffset.Now:O}] {ex}\n\n");
            }
            catch
            {
                // 日志写不进去也不能掩盖原始异常。
            }
            throw;
        }
    }

    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
