using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Vulnerator.View.UI;

namespace Vulnerator
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public App()
        {
            DispatcherUnhandledException += new System.Windows.Threading.DispatcherUnhandledExceptionEventHandler(App_DispatcherUnhandledException);
            Startup += new StartupEventHandler(App_Startup);
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
        }

        protected override void OnStartup(StartupEventArgs e)
        {
            // hook on error before app really starts
            AppDomain.CurrentDomain.UnhandledException += new UnhandledExceptionEventHandler(CurrentDomain_UnhandledException);
            Vulnerator.Properties.Settings.Default.Upgrade();
            Vulnerator.Properties.Settings.Default.Save();
            //AddListeners();
            base.OnStartup(e);
        }

        void Application_Startup(object sender, StartupEventArgs e)
        {
            if (Vulnerator.Properties.Settings.Default["Environment"].ToString().Equals("Undefined"))
            {
                SplashWindow splashWindow = new SplashWindow();
                splashWindow.Show();
            }
            else
            {
                MainWindow mainWindow = new MainWindow();
                mainWindow.Show();
            }
        }

        [Conditional("DEBUG")]
        private void AddListeners()
        {
            PresentationTraceSources.Refresh();
            PresentationTraceSources.DataBindingSource.Listeners.Add(new ConsoleTraceListener());
            PresentationTraceSources.DataBindingSource.Listeners.Add(new DebugTraceListener());
            PresentationTraceSources.DataBindingSource.Switch.Level = SourceLevels.Warning | SourceLevels.Error | SourceLevels.Critical;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            Vulnerator.Properties.Settings.Default.Save();
            base.OnExit(e);
        }

        void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            // Fatal: the process ends after this handler. Record why, then tell the user where to look.
            ReportError(e.ExceptionObject as Exception, true);
        }

        void App_DispatcherUnhandledException(object sender, System.Windows.Threading.DispatcherUnhandledExceptionEventArgs e)
        {
            ReportError(e.Exception, false);
            e.Handled = true;
        }

        void App_Startup(object sender, StartupEventArgs e)
        { AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException; }

        void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            // A background task failed without anyone waiting for it: log it, keep running, no dialog.
            Helper.LogWriter.LogErrorWithDebug("A background task failed.", e.Exception);
            e.SetObserved();
        }

        /// <summary>
        /// Logs an unexpected error with its details (to the Vulnerator log, or a file on the desktop if logging is
        /// not set up yet) and shows the user a short message saying where the details are.
        /// </summary>
        private static void ReportError(Exception exception, bool fatal)
        {
            string logPath = string.Empty;
            try
            {
                Helper.LogWriter.LogErrorWithDebug(fatal ? "Vulnerator stopped on an unexpected error." : "Unexpected error.", exception);
                logPath = Vulnerator.Properties.Settings.Default.LogPath;
            }
            catch
            { /* logging itself failed; fall back below */ }
            if (string.IsNullOrWhiteSpace(logPath) || logPath == "Undefined" || !File.Exists(logPath))
            {
                try
                {
                    logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "Vulnerator_ErrorLog.txt");
                    File.AppendAllText(logPath, $"{DateTime.Now:s}{Environment.NewLine}{exception}{Environment.NewLine}{Environment.NewLine}");
                }
                catch
                { logPath = "(could not be written)"; }
            }
            string message = (fatal ? "Vulnerator has to close because of an unexpected error." : "Vulnerator ran into an unexpected error; the last action may not have completed.") +
                             Environment.NewLine + Environment.NewLine + (exception?.Message ?? "Unknown error") +
                             Environment.NewLine + Environment.NewLine + "Details are in the log: " + logPath +
                             Environment.NewLine + "Report problems at " + Model.Object.GitHubActions.RepositoryUrl + "/issues";
            try
            { MessageBox.Show(message, "Vulnerator", MessageBoxButton.OK, fatal ? MessageBoxImage.Error : MessageBoxImage.Warning); }
            catch
            { /* no UI available */ }
        }
    }

    public class DebugTraceListener : TraceListener
    {
        public override void Write(string message)
        {
        }

        public override void WriteLine(string message)
        {
            Debugger.Break();
        }
    }
}
