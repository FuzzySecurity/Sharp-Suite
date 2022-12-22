using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace handle
{
    public class Helper
    {
        // Managed native buffer
        internal static IntPtr AllocManagedMemory(UInt32 iSize)
        {
            IntPtr pAlloc = Marshal.AllocHGlobal((Int32)iSize);
            API.RtlZeroMemory(pAlloc, iSize);
            
            return pAlloc;
        }
        
        // Free managed buffer
        internal static Boolean FreeManagedMemory(IntPtr pAlloc)
        {
            Marshal.FreeHGlobal(pAlloc);
            
            return true;
        }

        // Get an array of OBJECT_ALL_TYPES_INFORMATION, describing all object types
        // Win8+ only
        internal static List<API.OBJECT_TYPE_INFORMATION> GetObjectTypeInformation()
        {
            // Create return object
            List<API.OBJECT_TYPE_INFORMATION> loti = new List<API.OBJECT_TYPE_INFORMATION>();
            
            // Can we use this function?
            API.OSVERSIONINFOEX osInfo = new API.OSVERSIONINFOEX();
            API.RtlGetVersion(ref osInfo);
            if (osInfo.MajorVersion < 6 || (osInfo.MajorVersion == 6 && osInfo.MinorVersion < 2))
            {
                throw new AccessViolationException("[!] NtQueryObject->ObjectAllTypesInformation is only supported on Windows 8 and above.");
            }
            
            // Loop till success
            IntPtr pTypeInformation = IntPtr.Zero;
            UInt32 LoopSize = 0;
            while (true)
            {
                pTypeInformation = AllocManagedMemory(LoopSize);
                UInt32 iReturnLength = 0;
                UInt32 iCallRes = API.NtQueryObject(IntPtr.Zero, API.OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, pTypeInformation, LoopSize, ref iReturnLength);
                if (iCallRes == API.NTSTATUS_STATUS_INFO_LENGTH_MISMATCH)
                {
                    FreeManagedMemory(pTypeInformation);
                    LoopSize = Math.Max(LoopSize, iReturnLength);
                }
                else if (iCallRes == API.NTSTATUS_STATUS_SUCCESS)
                {
                    break;
                }
                else if (iCallRes == API.NTSTATUS_STATUS_ACCESS_DENIED)
                {
                    FreeManagedMemory(pTypeInformation);
                    throw new AccessViolationException("[!] Failed to query NtQueryObject: Access Denied");
                }
                else
                {
                    FreeManagedMemory(pTypeInformation);
                    throw new InvalidOperationException("[!] Failed to query NtQueryObject.");
                }
            }

            // Cast to OBJECT_ALL_TYPES_INFORMATION
            API.OBJECT_ALL_TYPES_INFORMATION oati = new API.OBJECT_ALL_TYPES_INFORMATION();
            oati = (API.OBJECT_ALL_TYPES_INFORMATION)Marshal.PtrToStructure(pTypeInformation, typeof(API.OBJECT_ALL_TYPES_INFORMATION));

            // Cast to OBJECT_TYPE_INFORMATION
            pTypeInformation = (IntPtr)(pTypeInformation.ToInt64() + IntPtr.Size);

            // Loop OBJECT_TYPE_INFORMATION structs
            for (Int32 i = 0; i < oati.NumberOfObjectTypes; i++)
            {
                // Cast to OBJECT_TYPE_INFORMATION
                API.OBJECT_TYPE_INFORMATION oti = (API.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(pTypeInformation, typeof(API.OBJECT_TYPE_INFORMATION));
                
                // Add to list
                loti.Add(oti);

                // Check the remainder oti.TypeName.MaximumLength divided by 8
                Int32 iRemainder = oti.TypeName.MaximumLength % 8;

                // Move pTypeInformation based on remainder
                // |_ String ptr is right after the struct
                if (iRemainder > 0)
                {
                    pTypeInformation = (IntPtr)(pTypeInformation.ToInt64() + Marshal.SizeOf(oti) + oti.TypeName.MaximumLength + (8-iRemainder));
                }
                else
                {
                    pTypeInformation = (IntPtr)(pTypeInformation.ToInt64() + Marshal.SizeOf(oti) + oti.TypeName.MaximumLength);
                }
            }

            // Return object
            return loti;
        }
        
        internal static List<API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> GetHandleInfoForPID(UInt32 ProcId)
        {
            // Create return object
            List<API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX> ltei = new List<API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX>();
            
            // Create Buffer variable
            IntPtr BuffPtr = IntPtr.Zero;

            // Loop till success
            UInt32 LoopSize = 0;
            while (true)
            {
                BuffPtr = AllocManagedMemory(LoopSize);
                UInt32 SystemInformationLength = 0;
                UInt32 CallRes = API.NtQuerySystemInformation(API.SystemExtendedHandleInformation, BuffPtr, LoopSize, ref SystemInformationLength);
                if (CallRes == API.NTSTATUS_STATUS_INFO_LENGTH_MISMATCH)
                {
                    FreeManagedMemory(BuffPtr);
                    LoopSize = Math.Max(LoopSize, SystemInformationLength);
                }
                else if (CallRes == API.NTSTATUS_STATUS_SUCCESS)
                {
                    break;
                }
                else if (CallRes == API.NTSTATUS_STATUS_ACCESS_DENIED)
                {
                    FreeManagedMemory(BuffPtr);
                    throw new AccessViolationException("[!] Failed to query SystemExtendedHandleInformation: Access Denied");
                }
                else
                {
                    FreeManagedMemory(BuffPtr);
                    throw new InvalidOperationException("[!] Failed to query SystemExtendedHandleInformation.");
                }
            }

            // Read handle count
            Int32 HandleCount = Marshal.ReadInt32(BuffPtr);

            // Move Buff ptr
            BuffPtr = (IntPtr)(BuffPtr.ToInt64() + (IntPtr.Size * 2));

            // Loop handles
            for (Int32 i = 0; i < HandleCount; i++)
            {
                UInt64 iCurrProcId = (UInt64)Marshal.ReadIntPtr((IntPtr)(BuffPtr.ToInt64() + IntPtr.Size));
                if (ProcId == iCurrProcId)
                {
                    // Ptr -> SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
                    API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX tei = new API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX();
                    tei = (API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)Marshal.PtrToStructure(BuffPtr, typeof(API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                    
                    // Add to list
                    ltei.Add(tei);
                }

                // Move Buffptr
                BuffPtr = (IntPtr)(BuffPtr.ToInt64() + Marshal.SizeOf(typeof(API.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)));
            }

            // Return list
            return ltei;
        }
    }
}