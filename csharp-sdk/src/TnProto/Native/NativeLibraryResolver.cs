using System.Reflection;
using System.Runtime.InteropServices;

namespace TnProto.Native;

internal static class NativeLibraryResolver
{
    private const string LibraryName = "tn_core_ffi";

    private static int s_registered;

    public static void Register()
    {
        if (Interlocked.Exchange(ref s_registered, 1) == 1)
        {
            return;
        }

        NativeLibrary.SetDllImportResolver(
            typeof(NativeLibraryResolver).Assembly,
            Resolve);
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, LibraryName, StringComparison.Ordinal))
        {
            return IntPtr.Zero;
        }

        foreach (var candidate in CandidatePaths())
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }

        return IntPtr.Zero;
    }

    private static IEnumerable<string> CandidatePaths()
    {
        var fileName = NativeFileName();
        var current = new DirectoryInfo(AppContext.BaseDirectory);

        while (current is not null)
        {
            yield return Path.Combine(current.FullName, "target", "debug", fileName);
            yield return Path.Combine(current.FullName, "target", "release", fileName);
            current = current.Parent;
        }
    }

    private static string NativeFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "tn_core_ffi.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libtn_core_ffi.dylib";
        }

        return "libtn_core_ffi.so";
    }
}
