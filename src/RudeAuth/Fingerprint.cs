using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace RudeAuth;

// Hardware fingerprint collection. These values are client-supplied and
// therefore forgeable: device binding deters casual licence sharing, it is not a
// control against a motivated attacker. The per-OS component set is the shared
// spec every RudeAuth SDK implements, so a device is recognised identically no
// matter which SDK authenticated it.
internal static class Fingerprint
{
    internal static string Label()
    {
        try
        {
            string n = Environment.MachineName;
            return string.IsNullOrEmpty(n) ? "unknown" : n;
        }
        catch { return "unknown"; }
    }

    // Collect gathers what this machine can report. Components that fail are
    // skipped, never substituted, because a placeholder shared across machines
    // would make unrelated devices look identical.
    internal static IReadOnlyList<string> Collect()
    {
        if (OperatingSystem.IsWindows()) return CollectWindows();
        if (OperatingSystem.IsLinux()) return CollectLinux();
        if (OperatingSystem.IsMacOS()) return CollectMacOS();
        return Array.Empty<string>();
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<string> CollectWindows()
    {
        var outp = new List<string>();
        void Push(string tag, string? v)
        {
            if (!string.IsNullOrEmpty(v)) outp.Add(tag + ":" + v);
        }
        Push("machine-guid", RegString(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid"));
        Push("volume", VolumeSerial());
        Push("cpu", RegString(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"));
        Push("bios", RegString(@"HARDWARE\DESCRIPTION\System\BIOS", "SystemSerialNumber"));
        Push("board", RegString(@"HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardProduct"));
        return outp;
    }

    [SupportedOSPlatform("windows")]
    private static string? RegString(string path, string name)
    {
        try
        {
            using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using RegistryKey? key = baseKey.OpenSubKey(path);
            return (key?.GetValue(name) as string)?.TrimEnd(' ', '\0');
        }
        catch { return null; }
    }

    [SupportedOSPlatform("windows")]
    private static string? VolumeSerial()
    {
        if (GetVolumeInformation(@"C:\", null, 0, out uint serial, out _, out _, null, 0) && serial != 0)
        {
            return serial.ToString("X8");
        }
        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeInformation(
        string rootPathName, StringBuilder? volumeNameBuffer, int volumeNameSize,
        out uint volumeSerialNumber, out uint maximumComponentLength, out uint fileSystemFlags,
        StringBuilder? fileSystemNameBuffer, int fileSystemNameSize);

    private static IReadOnlyList<string> CollectLinux()
    {
        var outp = new List<string>();
        void Push(string tag, string? v)
        {
            v = v?.Trim();
            if (!string.IsNullOrEmpty(v)) outp.Add(tag + ":" + v);
        }
        Push("machine-id", ReadFirstLine("/etc/machine-id"));
        Push("product-uuid", ReadFirstLine("/sys/class/dmi/id/product_uuid"));
        Push("board-serial", ReadFirstLine("/sys/class/dmi/id/board_serial"));
        Push("product-serial", ReadFirstLine("/sys/class/dmi/id/product_serial"));
        return outp;
    }

    private static string? ReadFirstLine(string path)
    {
        try { return System.IO.File.Exists(path) ? System.IO.File.ReadLines(path).FirstOrDefault() : null; }
        catch { return null; }
    }

    private static IReadOnlyList<string> CollectMacOS()
    {
        var outp = new List<string>();
        void Push(string tag, string? v)
        {
            v = v?.Trim();
            if (!string.IsNullOrEmpty(v)) outp.Add(tag + ":" + v);
        }
        Push("platform-uuid", IORegValue("IOPlatformUUID"));
        Push("serial", IORegValue("IOPlatformSerialNumber"));
        return outp;
    }

    private static string? IORegValue(string key)
    {
        try
        {
            var psi = new ProcessStartInfo("ioreg", "-rd1 -c IOPlatformExpertDevice")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
            };
            using Process? p = Process.Start(psi);
            if (p is null) return null;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            foreach (string line in output.Split('\n'))
            {
                if (line.Contains("\"" + key + "\""))
                {
                    int i = line.IndexOf("= ", StringComparison.Ordinal);
                    if (i >= 0) return line[(i + 2)..].Trim().Trim('"');
                }
            }
            return null;
        }
        catch { return null; }
    }
}
