using Microsoft.Win32.SafeHandles;

namespace TnProto.Native;

internal sealed class TnNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private TnNativeHandle()
        : base(ownsHandle: true)
    {
    }

    public static TnNativeHandle FromOwned(IntPtr handle)
    {
        if (handle == IntPtr.Zero)
        {
            throw new TnException(NativeBridge.LastError() ?? "native tn-proto call failed");
        }

        var safeHandle = new TnNativeHandle();
        safeHandle.SetHandle(handle);
        return safeHandle;
    }

    internal IntPtr RawHandle
    {
        get
        {
            if (IsInvalid || IsClosed)
            {
                throw new ObjectDisposedException(nameof(TnNativeHandle));
            }

            return handle;
        }
    }

    protected override bool ReleaseHandle()
    {
        return NativeMethods.RuntimeClose(handle) == 0;
    }
}
