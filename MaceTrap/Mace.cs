using System;
using System.IO;
using System.Runtime.InteropServices;

namespace MaceTrap
{
    class Mace
    {
        // Banner
        //-----------------------------------
        public static void PrintBanner()
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\n    /-|-\\   MACE                     ");
            Console.WriteLine("   [++++||<<>><<>>|===|+                ");
            Console.WriteLine("    \\-|-/    TRAP             ~b33f~ \n");
            Console.ResetColor();
        }

        public static void PrintHelp()
        {
            string HelpText = "\n >--~~--> Args? <--~~--<\n\n" +
                              "-l (-List)        List FileTime information for a file or folder\n" +
                              "-s (-Set)         Set FileTime information for a file or folder\n" +
                              "-d (-Duplicate)   Duplicate FileTime information from a file or folder\n" +
                              "-t (Time)         String DateTime representation; requires quotes if it contains spaces. All\n" +
                              "                  undefined elements are set randomly (YYYY-MM-DD is required!):\n" +
                              "                    =>  1999-10-20\n" +
                              "                    => \"2001-01-02 14:13\"\n" +
                              "                    => \"2019-02-19 01:01:01.111\"\n" +
                              "-c (-Create)      Boolean flag, overwrite CreationTime\n" +
                              "-a (-Access)      Boolean flag, overwrite LastAccessTime\n" +
                              "-w (-Write)       Boolean flag, overwrite LastWriteTime\n\n" +

                              " >--~~--> Usage? <--~~--<\n";

            Console.WriteLine(HelpText);
            ReturnStatusMessage("# List all FileTime elements", ConsoleColor.Green);
            Console.WriteLine("MaceTrap.exe -l C:\\Windows\\System32\\kernel32.dll");
            ReturnStatusMessage("# TimeStomp all FileTime elements", ConsoleColor.Green);
            Console.WriteLine("MaceTrap.exe -s C:\\Some\\Target\\file.folder -t \"2019-02-19 01:01:01.111\"");
            ReturnStatusMessage("# TimeStomp CreationTime & LastWriteTime; here HH:MM:SS,MS are randomized", ConsoleColor.Green);
            Console.WriteLine("MaceTrap.exe -s C:\\Some\\Target\\file.folder -t 1999-09-09 -c -w");
            ReturnStatusMessage("# TimeStomp a file/folder by duplicating the FileTime information from an existing file/folder", ConsoleColor.Green);
            Console.WriteLine("MaceTrap.exe -s C:\\Some\\Target\\file.folder -d C:\\Windows\\System32\\kernel32.dll");
        }

        // Structs
        //---------------------------
        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct VALIDTIME
        {
            public Boolean isValid;
            public DateTime dTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ALLDATETIME
        {
            public Boolean isValid;
            public DateTime CreationTime;
            public DateTime LastAccessTime;
            public DateTime LastWriteTime;
        }

        // APIs
        //---------------------------
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile(
            String lpFileName,
            int dwDesiredAccess,
            int dwShareMode,
            IntPtr securityAttrs,
            int dwCreationDisposition,
            int dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll")]
        public static extern Boolean GetFileTime(
            IntPtr hFile,
            ref FILETIME lpCreationTime,
            ref FILETIME lpLastAccessTime,
            ref FILETIME lpLastWriteTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean SetFileTime(
            IntPtr hFile,
            ref long lpCreationTime,
            ref long lpLastAccessTime,
            ref long lpLastWriteTime);

        [DllImport("kernel32.dll")]
        public static extern Boolean CloseHandle(
            IntPtr hObject);


        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        // Print status message
        public static void ReturnStatusMessage(String StatusMessage, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(StatusMessage);
            Console.ResetColor();
        }

        public static int VerifyPath(String Path)
        {
            // 0x0 == Invalid path
            // 0x1 == Is file
            // 0x2 == Is directory
            try
            {
                FileAttributes Attrib = File.GetAttributes(Path);
                if (Attrib == FileAttributes.Directory)
                {
                    return 0x2;
                } else
                {
                    return 0x1;
                }
            } catch
            {
                return 0x0;
            }
        }

        public static VALIDTIME VerifyStringTime(String StringTime)
        {
            VALIDTIME tData = new VALIDTIME();
            DateTime bDate = new DateTime();
            Random rand = new Random();

            try
            {
                bDate = DateTime.Parse(StringTime);
            } catch
            {
                tData.isValid = false;
                return tData;
            }

            // Rand any null values in the DateTime
            if (bDate.Millisecond == 0)
            {
                bDate = bDate.AddMilliseconds(rand.Next(1, 999));
            }

            if (bDate.Second == 0)
            {
                bDate = bDate.AddSeconds(rand.Next(1, 59));
            }

            if (bDate.Minute == 0)
            {
                bDate = bDate.AddMinutes(rand.Next(1, 59));
            }

            if (bDate.Hour == 0)
            {
                // More in line with working hours..
                bDate = bDate.AddHours(rand.Next(8, 18));
            }

            // Print res
            tData.isValid = true;
            tData.dTime = bDate;
            return tData;
        }

        public static ALLDATETIME GetTime(String Path)
        {
            IntPtr hFile = IntPtr.Zero;
            ALLDATETIME adt = new ALLDATETIME();

            // Check path
            int iFileType = VerifyPath(Path);
            if (iFileType == 0x0)
            {
                Console.WriteLine("[!] Invalid path specified: " + Path);
                adt.isValid = false;
                return adt;
            } else if (iFileType == 0x1)
            {
                // Open GENERIC_READ file handle
                hFile = CreateFile(Path, unchecked(((int)0x80000000)), 0x3, IntPtr.Zero, 0x3, 0x80, IntPtr.Zero);
            } else
            {
                // Open GENERIC_READ directory handle
                hFile = CreateFile(Path, unchecked(((int)0x80000000)), 0x3, IntPtr.Zero, 0x3, 0x2000000, IntPtr.Zero);
            }

            if (hFile == (IntPtr)(-1) || hFile == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to open object for read access: " + Path);
                Console.WriteLine("Error: " + GetLastError());
                adt.isValid = false;
                return adt;
            } else
            {
                FILETIME CreationTime = new FILETIME();
                FILETIME LastAccessTime = new FILETIME();
                FILETIME LastWriteTime = new FILETIME();
                Boolean bSuccess = GetFileTime(hFile, ref CreationTime, ref LastAccessTime, ref LastWriteTime);
                if (bSuccess)
                {
                    // Parse data
                    DateTime Create = DateTime.FromFileTimeUtc((((long)CreationTime.dwHighDateTime) << 32) | ((uint)CreationTime.dwLowDateTime));
                    DateTime LastA = DateTime.FromFileTimeUtc((((long)LastAccessTime.dwHighDateTime) << 32) | ((uint)LastAccessTime.dwLowDateTime));
                    DateTime LastW = DateTime.FromFileTimeUtc((((long)LastWriteTime.dwHighDateTime) << 32) | ((uint)LastWriteTime.dwLowDateTime));
                    Console.WriteLine("Path        : " + Path);
                    if (iFileType == 0x1)
                    {
                        Console.WriteLine("Type        : File");
                    } else
                    {
                        Console.WriteLine("Type        : Directory");
                    }
                    Console.WriteLine("Create Time : " + Create.ToUniversalTime().ToLocalTime());
                    Console.WriteLine("Last Access : " + LastA.ToUniversalTime().ToLocalTime());
                    Console.WriteLine("Last Write  : " + LastW.ToUniversalTime().ToLocalTime());

                    // Relase handle
                    CloseHandle(hFile);

                    adt.isValid = true;
                    adt.CreationTime = Create.ToUniversalTime().ToLocalTime();
                    adt.LastAccessTime = LastA.ToUniversalTime().ToLocalTime();
                    adt.LastWriteTime = LastW.ToUniversalTime().ToLocalTime();
                    return adt;
                } else
                {
                    Console.WriteLine("[!] Failed to read FileTime: " + Path);
                    adt.isValid = false;
                    return adt;
                }
            }
        }


        public static Boolean SetTime(String Path, DateTime Date, Boolean CreateTime, Boolean AccessTime, Boolean WriteTime, ALLDATETIME Duplicate = new ALLDATETIME())
        {
            IntPtr hFile = IntPtr.Zero;

            // Check path
            int iFileType = VerifyPath(Path);
            if (iFileType == 0x0)
            {
                Console.WriteLine("[!] Invalid path specified: " + Path);
                return false;
            }
            else if (iFileType == 0x1)
            {
                // Open FILE_WRITE_ATTRIBUTES file handle
                hFile = CreateFile(Path, 0x100, 0x3, IntPtr.Zero, 0x3, 0x80, IntPtr.Zero);
            }
            else
            {
                // Open FILE_WRITE_ATTRIBUTES directory handle
                hFile = CreateFile(Path, 0x100, 0x3, IntPtr.Zero, 0x3, 0x2000000, IntPtr.Zero);
            }

            if (hFile == (IntPtr)(-1) || hFile == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed to open object for write access: " + Path);
                Console.WriteLine("Error: " + GetLastError());
                return false;
            }
            else
            {
                Boolean bSuccess = false;

                if (Duplicate.isValid)
                {
                    // Dupe existing filetime
                    long Create = Duplicate.CreationTime.ToFileTime();
                    long Access = Duplicate.LastAccessTime.ToFileTime();
                    long Write  = Duplicate.LastWriteTime.ToFileTime();
                    bSuccess = SetFileTime(hFile, ref Create, ref Access, ref Write);
                } else
                {
                    long dt = Date.ToFileTime();
                    long NullTime = 0;

                    // Which elemets are we changing?
                    if (!CreateTime && !AccessTime && !WriteTime)
                    {
                        // Stomp all filetime's
                        bSuccess = SetFileTime(hFile, ref dt, ref dt, ref dt);
                    }
                    else
                    {
                        // Stomp combinations of filetime
                        if (CreateTime && !AccessTime && !WriteTime)
                        {
                            bSuccess = SetFileTime(hFile, ref dt, ref NullTime, ref NullTime);
                        }

                        if (CreateTime && AccessTime && !WriteTime)
                        {
                            bSuccess = SetFileTime(hFile, ref dt, ref dt, ref NullTime);
                        }

                        if (CreateTime && !AccessTime && WriteTime)
                        {
                            bSuccess = SetFileTime(hFile, ref dt, ref NullTime, ref dt);
                        }

                        if (!CreateTime && AccessTime && !WriteTime)
                        {
                            bSuccess = SetFileTime(hFile, ref NullTime, ref dt, ref NullTime);
                        }

                        if (!CreateTime && AccessTime && WriteTime)
                        {
                            bSuccess = SetFileTime(hFile, ref NullTime, ref dt, ref dt);
                        }

                        if (!CreateTime && !AccessTime && WriteTime)
                        {
                            bSuccess = SetFileTime(hFile, ref NullTime, ref NullTime, ref dt);
                        }
                    }
                }
                
                if (bSuccess)
                {
                    return true;
                } else
                {
                    return false;
                }
            }
        }


    }
}
