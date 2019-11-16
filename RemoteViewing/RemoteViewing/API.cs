using System;
using System.Runtime.InteropServices;

namespace RemoteViewing
{
    class API
    {
        // Native API's
        //-------------------------------------
        [DllImport("SspiCli.dll")]
        public static extern UInt32 SspiPrepareForCredRead(
            IntPtr AuthIdentity,
            IntPtr pszTargetName,
            IntPtr pCredmanCredentialType,
            IntPtr ppszCredmanTargetName);

        [DllImport("Credui.dll")]
        public static extern Boolean CredUnPackAuthenticationBufferW(
            UInt32 dwFlags,
            IntPtr pAuthBuffer,
            UInt32 cbAuthBuffer,
            IntPtr pszUserName,
            IntPtr pcchMaxUserName,
            IntPtr pszDomainName,
            IntPtr pcchMaxDomainName,
            IntPtr pszPassword,
            IntPtr pcchMaxPassword);

        // Delegates
        //-------------------------------------
        public struct DELEGATES
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 SspiPrepareForCredRead(
                IntPtr AuthIdentity,
                IntPtr pszTargetName,
                IntPtr pCredmanCredentialType,
                IntPtr ppszCredmanTargetName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean CredUnPackAuthenticationBufferW(
                UInt32 dwFlags,
                IntPtr pAuthBuffer,
                UInt32 cbAuthBuffer,
                IntPtr pszUserName,
                IntPtr pcchMaxUserName,
                IntPtr pszDomainName,
                IntPtr pcchMaxDomainName,
                IntPtr pszPassword,
                IntPtr pcchMaxPassword);
        }
    }
}