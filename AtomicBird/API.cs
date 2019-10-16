using System;
using System.Runtime.InteropServices;

namespace AtomicBird
{
    class API
    {
        // Native API's
        //-------------------------------------
        [DllImport("user32.dll")]
        public static extern int MessageBoxA(
            IntPtr hWnd,
            String text,
            String caption,
            int options);

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQuerySystemInformation(
            UInt32 SystemInformationClass,
            IntPtr SystemInformation,
            int SystemInformationLength,
            IntPtr ReturnLength);

        // Delegates
        //-------------------------------------
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate int MessageBoxA(
                IntPtr hWnd,
                String text,
                String caption,
                int options);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 NtQuerySystemInformation(
                UInt32 SystemInformationClass,
                IntPtr SystemInformation,
                int SystemInformationLength,
                IntPtr ReturnLength);
        }
    }
}
