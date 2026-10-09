// focus-helper.cs —— 「把 Electron 主窗口重新激活」的小工具
//
// 中文说明
// --------
// 这个 exe 是给 dsh-focus-guard / dsh-electron-dialog-focus-fix 用的：
// 原生对话框（confirm/alert/prompt）关掉之后，Chromium 的渲染进程仍然认为
// 自己没被激活（document.hasFocus() === false），于是页面收不到键盘输入。
//
// 为什么必须由「另一个进程」来做：
//   在同一个进程里把前台交出去之后，这个进程就失去了设置前台的权限
//   （Windows 前台锁定），此时再 SetForegroundWindow(自己) 会被直接拒绝。
//   而新进程天生有这个权限，所以由它代劳。
//
// 为什么是「切走再切回」而不是直接 SetForegroundWindow：
//   窗口已经在前台时，SetForegroundWindow 是空操作，连激活消息都不发，
//   所以什么也修不好。必须先真的把前台让出去，再拿回来，
//   Chromium 的 OnWidgetActivationChanged → RestoreFocus 链才会被走一遍。
//   切走用的目标窗口是 1x1 像素、WS_EX_TOOLWINDOW 的隐形窗口，肉眼无感。
//
// 模式：
//   focus-helper.exe [进程名] [--quiet] [--verbose] [--direct] [--check] [--log=文件]
//     默认     : 切走 + 切回（修复动作）
//     --direct : 只把目标窗口拉到前台，不做「切走」
//     --check  : 只报告「目标窗口当前是不是前台窗口」
//                exit 0 = 是（且没最小化）  1 = 不是  2 = 没找到窗口
//                给宿主插件的看门狗用（宿主跑在 Node 里，自己调不了 Win32）
//
// 进程名默认值可以用环境变量 DSH_FOCUS_PROCESS 覆盖（默认 "DeepSeek Harness"）。

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class FocusHelper
{
    private delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
    [DllImport("user32.dll")] private static extern IntPtr SetFocus(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern IntPtr SetActiveWindow(IntPtr hWnd);
    [DllImport("user32.dll")] private static extern bool AllowSetForegroundWindow(int dwProcessId);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hWnd, StringBuilder s, int nMax);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentProcessId();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(uint dwExStyle, string lpClassName, string lpWindowName,
        uint dwStyle, int x, int y, int nWidth, int nHeight,
        IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hWnd);

    private const int SW_RESTORE = 9;
    private const uint WS_POPUP = 0x80000000;
    private const uint WS_VISIBLE = 0x10000000;
    private const uint WS_EX_TOOLWINDOW = 0x00000080;

    private static bool verbose;
    private static string logPath;

    private static void Log(string message)
    {
        if (logPath == null) return;
        try
        {
            File.AppendAllText(logPath, DateTime.Now.ToString("HH:mm:ss.fff ") + message + Environment.NewLine);
        }
        catch { }
    }

    private static void Say(string message)
    {
        if (verbose) Console.WriteLine("focus-helper: " + message);
        Log(message);
    }

    private static string ClassOf(IntPtr hWnd)
    {
        var sb = new StringBuilder(256);
        GetClassNameW(hWnd, sb, 256);
        return sb.ToString();
    }

    /// <summary>1x1 pixel popup in the top-left corner; imperceptible, never in Alt+Tab.</summary>
    private static IntPtr CreateThrowawayWindow()
    {
        IntPtr h = CreateWindowExW(WS_EX_TOOLWINDOW, "Static", "dsh-focus-guard",
            WS_POPUP | WS_VISIBLE, 0, 0, 1, 1,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (h == IntPtr.Zero) Say("CreateWindowExW failed, err=" + Marshal.GetLastWin32Error());
        else Say("throwaway window created 0x" + h.ToString("X"));
        return h;
    }

    /// <summary>Any other visible top-level window we may hand the foreground to.</summary>
    private static IntPtr FindOtherWindow(IntPtr exclude)
    {
        IntPtr found = IntPtr.Zero;
        var preferred = new[] { "Progman", "Windows.UI.Core.CoreWindow", "Shell_TrayWnd" };
        foreach (string want in preferred)
        {
            EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
            {
                if (hWnd == exclude || !IsWindowVisible(hWnd)) return true;
                if (ClassOf(hWnd) == want) { found = hWnd; return false; }
                return true;
            }, IntPtr.Zero);
            if (found != IntPtr.Zero)
            {
                Say("fallback away-window: " + want + " 0x" + found.ToString("X"));
                return found;
            }
        }
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
        {
            if (hWnd == exclude || !IsWindowVisible(hWnd)) return true;
            string cls = ClassOf(hWnd);
            if (cls == "#32770" || cls == "Static") return true;
            RECT r;
            if (!GetWindowRect(hWnd, out r)) return true;
            if ((r.Right - r.Left) < 200 || (r.Bottom - r.Top) < 150) return true;
            found = hWnd;
            return false;
        }, IntPtr.Zero);
        if (found != IntPtr.Zero) Say("fallback away-window: 0x" + found.ToString("X") + " " + ClassOf(found));
        return found;
    }

    /// <summary>Biggest visible Chrome_WidgetWin_1 owned by the app = the real window.</summary>
    private static IntPtr FindMainWindow(HashSet<uint> wanted)
    {
        IntPtr target = IntPtr.Zero;
        long bestArea = -1;
        EnumWindows(delegate(IntPtr hWnd, IntPtr lParam)
        {
            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            if (!wanted.Contains(pid) || !IsWindowVisible(hWnd)) return true;
            if (ClassOf(hWnd) != "Chrome_WidgetWin_1") return true;
            RECT r;
            if (!GetWindowRect(hWnd, out r)) return true;
            long area = (long)(r.Right - r.Left) * (r.Bottom - r.Top);
            if (area > bestArea) { bestArea = area; target = hWnd; }
            return true;
        }, IntPtr.Zero);
        return target;
    }

    private static int Main(string[] args)
    {
        // 进程名默认值可由环境变量覆盖，便于复用到其它 Electron 应用
        string processName = Environment.GetEnvironmentVariable("DSH_FOCUS_PROCESS");
        if (string.IsNullOrEmpty(processName)) processName = "DeepSeek Harness";
        bool quiet = false;
        bool direct = false;
        bool check = false;
        bool sawName = false;
        foreach (string a in args)
        {
            if (a.StartsWith("--"))
            {
                if (a == "--quiet") quiet = true;
                else if (a == "--verbose") verbose = true;
                else if (a == "--direct") direct = true;
                else if (a == "--check") check = true;
                else if (a.StartsWith("--log=")) logPath = a.Substring(6);
            }
            else if (!sawName)
            {
                processName = a;
                sawName = true;
            }
        }
        if (verbose) quiet = false;

        Say("pid=" + GetCurrentProcessId() + " target=" + processName + " direct=" + direct + " check=" + check);

        Process[] procs;
        try { procs = Process.GetProcessesByName(processName); }
        catch (Exception e) { Say("GetProcessesByName failed: " + e.Message); return 1; }
        if (procs.Length == 0) { Say("no process named " + processName); return 1; }

        var wanted = new HashSet<uint>();
        foreach (Process p in procs)
        {
            try { wanted.Add((uint)p.Id); } catch { } finally { p.Dispose(); }
        }

        IntPtr target = FindMainWindow(wanted);
        if (target == IntPtr.Zero) { Say("no candidate window"); if (!quiet && check) Console.WriteLine("focus-helper: check no-window"); return 2; }

        // --- --check mode: is the app window the current foreground window?
        if (check)
        {
            bool isFg = (GetForegroundWindow() == target) && !IsIconic(target);
            Say("check hwnd=0x" + target.ToString("X") + " isForeground=" + isFg + " iconic=" + IsIconic(target));
            if (!quiet) Console.WriteLine("focus-helper: check hwnd=" + target + " isForeground=" + isFg);
            return isFg ? 0 : 1;
        }

        long bestArea = -1;
        {
            RECT r;
            if (GetWindowRect(target, out r)) bestArea = (long)(r.Right - r.Left) * (r.Bottom - r.Top);
        }
        Say("target=0x" + target.ToString("X") + " area=" + bestArea + " foreground=0x" + GetForegroundWindow().ToString("X"));

        AllowSetForegroundWindow(-1);
        if (IsIconic(target)) ShowWindow(target, SW_RESTORE);

        bool alreadyForeground = (GetForegroundWindow() == target);
        string mode = direct ? "direct-forced" : "switch-away";
        Say("alreadyForeground=" + alreadyForeground);

        // --- the switch-away step: always performed, because a plain
        // SetForegroundWindow is a no-op when the window is already foreground and
        // does not reliably activate the renderer when coming from the background.
        if (!direct)
        {
            IntPtr away = CreateThrowawayWindow();
            bool destroyAway = away != IntPtr.Zero;
            if (away == IntPtr.Zero) away = FindOtherWindow(target);
            if (away != IntPtr.Zero)
            {
                AllowSetForegroundWindow(-1);
                bool okAway = SetForegroundWindow(away);
                Say("switch away to 0x" + away.ToString("X") + " -> " + okAway);
                Thread.Sleep(120);
                if (destroyAway) DestroyWindow(away);
                Thread.Sleep(30);
            }
            else
            {
                Say("no away-window available; falling back to direct foreground");
                mode = "direct-nofallback";
            }
        }

        AllowSetForegroundWindow(-1);
        Say("SetForegroundWindow(target)=" + SetForegroundWindow(target));
        SetFocus(target);
        SetActiveWindow(target);

        bool ok = false;
        for (int i = 0; i < 16; i++)
        {
            Thread.Sleep(50);
            if (GetForegroundWindow() == target) { ok = true; Say("foreground reached target after " + ((i + 1) * 50) + "ms"); break; }
        }

        Say("result: ok=" + ok + " mode=" + mode + " foreground=0x" + GetForegroundWindow().ToString("X"));
        if (!quiet) Console.WriteLine("focus-helper: hwnd=" + target + " ok=" + ok + " mode=" + mode);
        return ok ? 0 : 3;
    }
}
