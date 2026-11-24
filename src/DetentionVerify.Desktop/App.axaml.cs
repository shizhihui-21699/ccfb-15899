using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml.Styling;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;
using Avalonia.Platform;
using DetentionVerify.Core;
using DetentionVerify.Desktop.ViewModels;
using DetentionVerify.Desktop.Views;

namespace DetentionVerify.Desktop;

public sealed class App : Application
{
    public override void Initialize()
    {
        Styles.Add(new FluentTheme());
        RequestedThemeVariant = ThemeVariant.Light;

        // 窗口机器常年高亮、白天反光，统一走浅色高对比，不跟随系统深色。
        Resources["AppFontFamily"] = new FontFamily("Microsoft YaHei UI, Microsoft YaHei, PingFang SC, Noto Sans CJK SC, Source Han Sans SC, sans-serif");

        foreach (var uri in new[]
                 {
                     "avares://DetentionVerify/Assets/Styles/Tokens.axaml",
                     "avares://DetentionVerify/Assets/Styles/Controls.axaml",
                 })
        {
            try { Styles.Add(new StyleInclude(new Uri("avares://DetentionVerify/")) { Source = new Uri(uri) }); }
            catch (Exception) { /* 资源缺失不应阻止程序启动 */ }
        }
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var services = AppServices.Create();
            var window = new MainWindow { DataContext = new MainWindowViewModel(services) };
            desktop.MainWindow = window;
            desktop.ShutdownMode = Avalonia.Controls.ShutdownMode.OnMainWindowClose;
        }

        base.OnFrameworkInitializationCompleted();
    }
}

/// <summary>极简服务定位。窗口程序不需要容器，但数据库路径、密钥等集中在一处便于审计。</summary>
public sealed class AppServices
{
    public required SqliteStore Store { get; init; }
    public required VerificationEngine Engine { get; init; }
    public required SessionService Sessions { get; init; }
    public required RosterImporter Importer { get; init; }
    public required RosterPolicy Policy { get; init; }
    public required Settings Settings { get; init; }

    public static AppServices Create()
    {
        var dataDir = Settings.ResolveDataDirectory();
        var store = new SqliteStore(Path.Combine(dataDir, "detention-verify.db"));
        var settings = Settings.Load(dataDir);

        // 首次运行生成窗口每日密钥；若配置文件里已指定则以配置为准。
        if (string.IsNullOrWhiteSpace(settings.WindowSecret))
        {
            settings.WindowSecret = Convert.ToBase64String(
                System.Security.Cryptography.RandomNumberGenerator.GetBytes(24));
            settings.Save(dataDir);
        }

        return new AppServices
        {
            Store = store,
            Engine = new VerificationEngine(store),
            Sessions = new SessionService(store),
            Importer = new RosterImporter(store),
            Policy = RosterPolicy.Default,
            Settings = settings,
        };
    }
}
