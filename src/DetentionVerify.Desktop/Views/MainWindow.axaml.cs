using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using DetentionVerify.Desktop.ViewModels;

namespace DetentionVerify.Desktop.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // 高峰时窗口人员不离开键盘：证号框默认获得焦点，Esc 清空，F2 授权。
        Opened += (_, _) => FocusCertBox();
        KeyDown += OnGlobalKeyDown;
    }

    private void FocusCertBox()
    {
        var box = this.FindControl<TextBox>("CertBox");
        box?.Focus();
        box?.SelectAll();
    }

    private void OnCertKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key is Key.Enter or Key.Return && DataContext is MainWindowViewModel vm)
        {
            vm.VerifyCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void OnOpenAdmin(object? sender, RoutedEventArgs e) => OpenAdmin();

    private void OpenAdmin()
    {
        if (DataContext is not MainWindowViewModel vm) return;
        var admin = new AdminWindow { DataContext = new AdminViewModel(vm.Services) };
        admin.ShowDialog(this);
    }

    private void OnGlobalKeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainWindowViewModel vm) return;

        switch (e.Key)
        {
            case Key.Escape:
                vm.ClearCommand.Execute(null);
                FocusCertBox();
                e.Handled = true;
                break;

            case Key.F2:
                if (vm.CanAuthorize)
                {
                    vm.AuthorizeCommand.Execute(null);
                    e.Handled = true;
                }
                break;

            case Key.F5:
                vm.RefreshRosterCommand.Execute(null);
                vm.RefreshRecentCommand.Execute(null);
                e.Handled = true;
                break;

            case Key.A when e.KeyModifiers.HasFlag(KeyModifiers.Control | KeyModifiers.Shift):
                OpenAdmin();
                e.Handled = true;
                break;
        }
    }
}
