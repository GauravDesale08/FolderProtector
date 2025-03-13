using System;
using System.IO;
using System.Windows.Forms;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace FolderProtector
{
    public partial class MainForm : Form
    {
        // Configuration - CHANGE THESE VALUES
        private const string FolderToProtect = @"C:\Users\Gaurav\Desktop\demo";
        private const string Username = "admin";
        private const string Password = "secure123";

        // Windows API for file system monitoring
        private FileSystemWatcher watcher;
        private bool isAuthenticated = false;

        // Keep track of application running status
        private static Mutex mutex = new Mutex(true, "FolderProtectorInstance");
        private NotifyIcon trayIcon;

        // Windows API imports for folder access interception
        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);
        private static IntPtr hookId = IntPtr.Zero;
        private static HookProc hookProcDelegate;

        // Hook constants
        private const int WH_SHELL = 10;
        private const int HSHELL_WINDOWCREATED = 1;

        public MainForm()
        {
            InitializeComponent();
            InitializeTrayIcon();
            ProtectFolder();
            StartFileSystemWatcher();
            SetupShellHook();

            // Set application to start with Windows
            SetStartWithWindows(true);

            // Hide form on startup
            this.WindowState = FormWindowState.Minimized;
            this.ShowInTaskbar = false;
        }

        private void InitializeComponent()
        {
            this.SuspendLayout();
            // 
            // MainForm
            // 
            this.ClientSize = new System.Drawing.Size(284, 261);
            this.Name = "MainForm";
            this.Text = "Folder Protector";
            this.Load += new System.EventHandler(this.MainForm_Load);
            this.FormClosing += new FormClosingEventHandler(this.MainForm_FormClosing);
            this.ResumeLayout(false);
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {
            // Unhook the shell hook when the application is closing
            if (hookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(hookId);
                hookId = IntPtr.Zero;
            }
        }

        private void SetupShellHook()
        {
            // Create a hook to monitor window creation
            hookProcDelegate = new HookProc(ShellProc);
            hookId = SetWindowsHookEx(WH_SHELL, hookProcDelegate,
                        GetModuleHandle(null), 0);
        }

        private IntPtr ShellProc(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam.ToInt32() == HSHELL_WINDOWCREATED)
            {
                // Check if Explorer is trying to access our folder
                // This is simplified - in a real app you'd get the window title and check
                if (!isAuthenticated)
                {
                    if (IsFolderBeingAccessed())
                    {
                        this.Invoke(new Action(() =>
                        {
                            ShowAuthenticationDialog();
                        }));
                    }
                }
            }

            return CallNextHookEx(hookId, nCode, wParam, lParam);
        }

        private bool IsFolderBeingAccessed()
        {
            // This is a simplified check that won't be 100% accurate
            // A more robust solution would involve additional Windows API calls
            // to get information about the newly created window

            // For demonstration, we'll use the FileSystemWatcher events as a backup
            return true;
        }

        private void InitializeTrayIcon()
        {
            trayIcon = new NotifyIcon();
            trayIcon.Icon = System.Drawing.SystemIcons.Shield;
            trayIcon.Text = "Folder Protector";
            trayIcon.Visible = true;

            // Create context menu
            ContextMenu menu = new ContextMenu();
            menu.MenuItems.Add("Access Protected Folder", OnAccessFolder);
            menu.MenuItems.Add("-");
            menu.MenuItems.Add("Exit", OnExit);
            trayIcon.ContextMenu = menu;

            trayIcon.DoubleClick += TrayIcon_DoubleClick;
        }

        private void OnAccessFolder(object sender, EventArgs e)
        {
            // Show authentication dialog when user selects "Access Protected Folder"
            ShowAuthenticationDialog();
        }

        private void TrayIcon_DoubleClick(object sender, EventArgs e)
        {
            // Show authentication dialog when tray icon is double-clicked
            ShowAuthenticationDialog();
        }

        private void OnExit(object sender, EventArgs e)
        {
            // Restore folder permissions before exiting
            try
            {
                RestoreDefaultPermissions(FolderToProtect);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error restoring permissions: " + ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

            trayIcon.Visible = false;
            Application.Exit();
        }

        private void MainForm_Load(object sender, EventArgs e)
        {
            // Check if application is already running
            if (!mutex.WaitOne(0, false))
            {
                MessageBox.Show("Folder Protector is already running.",
                    "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Application.Exit();
                return;
            }

            // Hide the main form
            this.Hide();
        }

        private void SetStartWithWindows(bool enable)
        {
            try
            {
                RegistryKey key = Registry.CurrentUser.OpenSubKey(
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);

                if (enable)
                {
                    key.SetValue("FolderProtector", Application.ExecutablePath);
                }
                else
                {
                    key.DeleteValue("FolderProtector", false);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error setting startup: " + ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ProtectFolder()
        {
            try
            {
                if (!Directory.Exists(FolderToProtect))
                {
                    MessageBox.Show("Protected folder does not exist: " + FolderToProtect,
                        "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                // Set folder attributes to read-only but NOT hidden
                File.SetAttributes(FolderToProtect,
                    File.GetAttributes(FolderToProtect) | FileAttributes.ReadOnly);

                // Create a dummy file in the folder to indicate it's protected
                string indicatorFile = Path.Combine(FolderToProtect, "PROTECTED_FOLDER.txt");
                if (!File.Exists(indicatorFile))
                {
                    using (StreamWriter sw = File.CreateText(indicatorFile))
                    {
                        sw.WriteLine("This folder is protected by Folder Protector.");
                        sw.WriteLine("Right-click the shield icon in the system tray to access this folder.");
                    }

                    // Make the indicator file read-only
                    File.SetAttributes(indicatorFile, FileAttributes.ReadOnly);
                }

                // Apply additional file system security to prevent browsing
                DirectorySecurity dirSecurity = Directory.GetAccessControl(FolderToProtect);
                dirSecurity.SetAccessRuleProtection(true, false);

                // Get current user
                WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                SecurityIdentifier currentUserSid = currentUser.User;

                // Create a new rule to allow listing folder contents but deny file access
                FileSystemAccessRule allowListRule = new FileSystemAccessRule(
                    currentUserSid,
                    FileSystemRights.ListDirectory,
                    InheritanceFlags.None,
                    PropagationFlags.None,
                    AccessControlType.Allow);

                FileSystemAccessRule denyAccessRule = new FileSystemAccessRule(
                    currentUserSid,
                    FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Modify | FileSystemRights.Delete,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Deny);

                dirSecurity.AddAccessRule(allowListRule);
                dirSecurity.AddAccessRule(denyAccessRule);

                // Apply the updated security settings
                Directory.SetAccessControl(FolderToProtect, dirSecurity);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error setting up folder protection: " + ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void StartFileSystemWatcher()
        {
            try
            {
                // Get the parent directory
                string parentDirectory = Path.GetDirectoryName(FolderToProtect);
                string folderName = Path.GetFileName(FolderToProtect);

                // Create a new FileSystemWatcher
                watcher = new FileSystemWatcher();
                watcher.Path = parentDirectory;

                // Watch for all actions
                watcher.NotifyFilter = NotifyFilters.LastAccess
                                    | NotifyFilters.LastWrite
                                    | NotifyFilters.FileName
                                    | NotifyFilters.DirectoryName
                                    | NotifyFilters.Attributes
                                    | NotifyFilters.Security;

                // Watch all events for the specific folder
                watcher.Filter = folderName;

                // Add event handlers for all events
                watcher.Changed += OnFolderEvent;
                watcher.Created += OnFolderEvent;
                watcher.Deleted += OnFolderEvent;
                watcher.Renamed += OnFolderEvent;

                // Begin watching
                watcher.EnableRaisingEvents = true;

                // Add a secondary watcher for the folder contents
                if (Directory.Exists(FolderToProtect))
                {
                    FileSystemWatcher contentWatcher = new FileSystemWatcher();
                    contentWatcher.Path = FolderToProtect;
                    contentWatcher.IncludeSubdirectories = true;
                    contentWatcher.NotifyFilter = NotifyFilters.LastAccess
                                               | NotifyFilters.LastWrite
                                               | NotifyFilters.FileName
                                               | NotifyFilters.DirectoryName;

                    contentWatcher.Changed += OnContentEvent;
                    contentWatcher.Created += OnContentEvent;
                    contentWatcher.Deleted += OnContentEvent;
                    contentWatcher.Renamed += OnContentEvent;

                    // Begin watching folder contents
                    contentWatcher.EnableRaisingEvents = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error setting up file system watcher: " + ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void OnContentEvent(object source, FileSystemEventArgs e)
        {
            // If folder content is accessed and user is not authenticated
            if (!isAuthenticated)
            {
                this.Invoke(new Action(ShowAuthenticationDialog));
            }
        }

        private void OnFolderEvent(object source, FileSystemEventArgs e)
        {
            // If folder is accessed and user is not authenticated
            if (!isAuthenticated)
            {
                this.Invoke(new Action(ShowAuthenticationDialog));
            }
        }

        private void ShowAuthenticationDialog()
        {
            // Ensure we're running on the UI thread
            if (InvokeRequired)
            {
                Invoke(new Action(ShowAuthenticationDialog));
                return;
            }

            using (var form = new Form())
            {
                form.Text = "Authentication Required";
                form.Size = new System.Drawing.Size(350, 200);
                form.StartPosition = FormStartPosition.CenterScreen;
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;
                form.TopMost = true;

                // Title label
                Label titleLabel = new Label();
                titleLabel.Text = "Enter credentials to access folder";
                titleLabel.Font = new System.Drawing.Font("Arial", 12, System.Drawing.FontStyle.Bold);
                titleLabel.Location = new System.Drawing.Point(10, 10);
                titleLabel.Size = new System.Drawing.Size(330, 20);
                form.Controls.Add(titleLabel);

                // Username label
                Label userLabel = new Label();
                userLabel.Text = "Username:";
                userLabel.Location = new System.Drawing.Point(10, 50);
                userLabel.Size = new System.Drawing.Size(100, 20);
                form.Controls.Add(userLabel);

                // Username textbox
                TextBox userTextBox = new TextBox();
                userTextBox.Location = new System.Drawing.Point(120, 50);
                userTextBox.Size = new System.Drawing.Size(200, 20);
                form.Controls.Add(userTextBox);

                // Password label
                Label pwdLabel = new Label();
                pwdLabel.Text = "Password:";
                pwdLabel.Location = new System.Drawing.Point(10, 80);
                pwdLabel.Size = new System.Drawing.Size(100, 20);
                form.Controls.Add(pwdLabel);

                // Password textbox
                TextBox pwdTextBox = new TextBox();
                pwdTextBox.Location = new System.Drawing.Point(120, 80);
                pwdTextBox.Size = new System.Drawing.Size(200, 20);
                pwdTextBox.PasswordChar = '*';
                form.Controls.Add(pwdTextBox);

                // OK button
                Button okButton = new Button();
                okButton.Text = "Login";
                okButton.DialogResult = DialogResult.OK;
                okButton.Location = new System.Drawing.Point(120, 120);
                okButton.Size = new System.Drawing.Size(90, 30);
                form.Controls.Add(okButton);
                form.AcceptButton = okButton;

                // Cancel button
                Button cancelButton = new Button();
                cancelButton.Text = "Cancel";
                cancelButton.DialogResult = DialogResult.Cancel;
                cancelButton.Location = new System.Drawing.Point(230, 120);
                cancelButton.Size = new System.Drawing.Size(90, 30);
                form.Controls.Add(cancelButton);
                form.CancelButton = cancelButton;

                // Show the form
                DialogResult result = form.ShowDialog();

                if (result == DialogResult.OK)
                {
                    // Verify credentials
                    if (userTextBox.Text == Username && pwdTextBox.Text == Password)
                    {
                        // Authentication successful
                        isAuthenticated = true;

                        // Temporarily restore access and open the folder
                        RestoreDefaultPermissions(FolderToProtect);
                        Process.Start("explorer.exe", FolderToProtect);

                        // Set a timer to revoke access after a period
                        System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
                        timer.Interval = 60000; // 1 minute (adjust as needed)
                        timer.Tick += (s, e) => {
                            isAuthenticated = false;
                            ProtectFolder(); // Re-protect the folder
                            timer.Stop();
                            timer.Dispose();
                        };
                        timer.Start();
                    }
                    else
                    {
                        // Authentication failed
                        MessageBox.Show("Invalid username or password.", "Access Denied",
                            MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void RestoreDefaultPermissions(string folderPath)
        {
            try
            {
                // Remove read-only attribute, but keep the folder visible
                FileAttributes attributes = File.GetAttributes(folderPath);
                File.SetAttributes(folderPath, attributes & ~FileAttributes.ReadOnly);

                // Restore standard permissions
                DirectorySecurity dirSecurity = Directory.GetAccessControl(folderPath);
                dirSecurity.SetAccessRuleProtection(false, true);
                Directory.SetAccessControl(folderPath, dirSecurity);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error restoring permissions: " + ex.Message,
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}