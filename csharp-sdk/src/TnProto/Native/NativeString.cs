using System.Runtime.InteropServices;

namespace TnProto.Native;

internal static class NativeString
{
    public static string? Consume(IntPtr value)
    {
        if (value == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUTF8(value);
        }
        finally
        {
            NativeMethods.StringFree(value);
        }
    }
}
