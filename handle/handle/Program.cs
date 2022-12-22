using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace handle
{
    internal class Program
    {
        internal static void getTypeInformation()
        {
            List<API.OBJECT_TYPE_INFORMATION> lTypes = Helper.GetObjectTypeInformation();
            foreach (API.OBJECT_TYPE_INFORMATION type in lTypes)
            {
                Console.WriteLine("\n[+] Object Type --> {0}", Marshal.PtrToStringUni(type.TypeName.Buffer));
                Console.WriteLine("    |_ TotalNumberOfObjects       : {0}", type.TotalNumberOfObjects);
                Console.WriteLine("    |_ TotalNumberOfHandles       : {0}", type.TotalNumberOfHandles);
                Console.WriteLine("    |_ TotalPagedPoolUsage        : {0}", type.TotalPagedPoolUsage);
                Console.WriteLine("    |_ TotalNonPagedPoolUsage     : {0}", type.TotalNonPagedPoolUsage);
                Console.WriteLine("    |_ TotalNamePoolUsage         : {0}", type.TotalNamePoolUsage);
                Console.WriteLine("    |_ TotalHandleTableUsage      : {0}", type.TotalHandleTableUsage);
                Console.WriteLine("    |_ HighWaterNumberOfObjects   : {0}", type.HighWaterNumberOfObjects);
                Console.WriteLine("    |_ HighWaterNumberOfHandles   : {0}", type.HighWaterNumberOfHandles);
                Console.WriteLine("    |_ HighWaterPagedPoolUsage    : {0}", type.HighWaterPagedPoolUsage);
                Console.WriteLine("    |_ HighWaterNonPagedPoolUsage : {0}", type.HighWaterNonPagedPoolUsage);
                Console.WriteLine("    |_ HighWaterNamePoolUsage     : {0}", type.HighWaterNamePoolUsage);
                Console.WriteLine("    |_ HighWaterHandleTableUsage  : {0}", type.HighWaterHandleTableUsage);
                Console.WriteLine("    |_ InvalidAttributes          : 0x{0:X}", type.InvalidAttributes);
                Console.WriteLine("    |_ GenericMapping");
                Console.WriteLine("    |  |_ GenericRead             : 0x{0:X}", type.GenericMapping.GenericRead);
                Console.WriteLine("    |  |_ GenericWrite            : 0x{0:X}", type.GenericMapping.GenericWrite);
                Console.WriteLine("    |  |_ GenericExecute          : 0x{0:X}", type.GenericMapping.GenericExecute);
                Console.WriteLine("    |  |_ GenericAll              : 0x{0:X}", type.GenericMapping.GenericAll);
                Console.WriteLine("    |_ ValidAccessMask            : 0x{0:X}", type.ValidAccessMask);
                Console.WriteLine("    |_ SecurityRequired           : {0}", type.SecurityRequired);
                Console.WriteLine("    |_ MaintainHandleCount        : {0}", type.MaintainHandleCount);
                Console.WriteLine("    |_ TypeIndex                  : 0x{0:X}", type.TypeIndex);
                Console.WriteLine("    |_ ReservedByte               : {0}", type.ReservedByte);
                Console.WriteLine("    |_ PoolType                   : {0}", (API.POOL_TYPE)type.PoolType);
                Console.WriteLine("    |_ DefaultPagedPoolCharge     : {0}", type.DefaultPagedPoolCharge);
                Console.WriteLine("    |_ DefaultNonPagedPoolCharge  : {0}", type.DefaultNonPagedPoolCharge);
            }
        }

        internal static void getHadleInformationForProcess(UInt32 iPID)
        {
            // Get all handles for this process
            List<API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> lHandles = Helper.GetHandleInfoForPID(iPID);
            
            // Get all object types
            List<API.OBJECT_TYPE_INFORMATION> lTypes = Helper.GetObjectTypeInformation();
            
            // Print out all handles for this process
            foreach (API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle in lHandles)
            {
                // Get the object type for this handle
                API.OBJECT_TYPE_INFORMATION type = lTypes.Find(delegate(API.OBJECT_TYPE_INFORMATION t) { return t.TypeIndex == handle.ObjectTypeIndex; });
                
                // Print out API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
                Console.WriteLine("\n[+] Handle --> 0x{0:X}", handle.HandleValue);
                Console.WriteLine("    |_ Object Type           : {0}", Marshal.PtrToStringUni(type.TypeName.Buffer));
                Console.WriteLine("    |_ GrantedAccess         : 0x{0:X}", handle.GrantedAccess);
                Console.WriteLine("    |_ Object                : 0x{0:X}", handle.Object.ToInt64());
            }
        }
        
        public static void Main(string[] args)
        {
            // arg parse
            Int32 iType = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(t|Type)$").Match(s).Success);
            Int32 iProcess = Array.FindIndex(args, s => new Regex(@"(?i)(-|--|/)(p|Process)$").Match(s).Success);
            
            if (iType != -1)
            {
                getTypeInformation();
            } else if (iProcess != -1)
            {
                try
                {
                    UInt32 iPID = UInt32.Parse(args[(iProcess + 1)]);
                    getHadleInformationForProcess(iPID);
                } catch
                {
                    Console.WriteLine("[!] Please specify a valid process id (-p|Process)");
                }
            } else
            {
                Console.WriteLine("Usage: handle.exe -t|Type");
                Console.WriteLine("       handle.exe -p|Process <PID>");
            }
        }
    }
}