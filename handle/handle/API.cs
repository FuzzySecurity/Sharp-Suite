using System;
using System.Runtime.InteropServices;

namespace handle
{
    public class API
    {
        // Constants
        //=================================================
        
        internal static UInt32 NTSTATUS_STATUS_SUCCESS = 0x0;
        internal static UInt32 NTSTATUS_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        internal static UInt32 NTSTATUS_STATUS_ACCESS_DENIED = 0xC0000022;
        
        // API Constants
        internal static UInt32 SystemExtendedHandleInformation = 0x40;
        
        // Structs
        //=================================================
        
        [StructLayout(LayoutKind.Sequential)]
        public struct OSVERSIONINFOEX
        {
            public UInt32 OSVersionInfoSize;
            public UInt32 MajorVersion;
            public UInt32 MinorVersion;
            public UInt32 BuildNumber;
            public UInt32 PlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public String CSDVersion;
            public UInt16 ServicePackMajor;
            public UInt16 ServicePackMinor;
            public UInt16 SuiteMask;
            public Byte ProductType;
            public Byte Reserved;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct GENERIC_MAPPING
        {
            public UInt32 GenericRead;
            public UInt32 GenericWrite;
            public UInt32 GenericExecute;
            public UInt32 GenericAll;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public UInt32 TotalNumberOfObjects;
            public UInt32 TotalNumberOfHandles;
            public UInt32 TotalPagedPoolUsage;
            public UInt32 TotalNonPagedPoolUsage;
            public UInt32 TotalNamePoolUsage;
            public UInt32 TotalHandleTableUsage;
            public UInt32 HighWaterNumberOfObjects;
            public UInt32 HighWaterNumberOfHandles;
            public UInt32 HighWaterPagedPoolUsage;
            public UInt32 HighWaterNonPagedPoolUsage;
            public UInt32 HighWaterNamePoolUsage;
            public UInt32 HighWaterHandleTableUsage;
            public UInt32 InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public UInt32 ValidAccessMask;
            public Byte SecurityRequired;
            public Byte MaintainHandleCount;
            public Byte TypeIndex;
            public Byte ReservedByte;
            public UInt32 PoolType;
            public UInt32 DefaultPagedPoolCharge;
            public UInt32 DefaultNonPagedPoolCharge;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_ALL_TYPES_INFORMATION
        {
            public UInt32 NumberOfObjectTypes;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_HANDLE_INFORMATION_EX
        {
            public IntPtr NumberOfHandles;
            public IntPtr Reserved;
            public SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX[] Handles;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public IntPtr UniqueProcessId;
            public IntPtr HandleValue;
            public UInt32 GrantedAccess;
            public UInt16 CreatorBackTraceIndex;
            public UInt16 ObjectTypeIndex;
            public UInt32 HandleAttributes;
            public UInt32 Reserved;
        }
        
        // Enums
        //=================================================
        
        internal enum OBJECT_INFORMATION_CLASS
        {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2,
            ObjectAllTypesInformation = 3,
            ObjectHandleInformation = 4
        }
        
        internal enum POOL_TYPE
        {
            NonPagedPool,
            NonPagedPoolExecute = NonPagedPool,
            PagedPool,
            NonPagedPoolMustSucceed = NonPagedPool + 2,
            DontUseThisType,
            NonPagedPoolCacheAligned = NonPagedPool + 4,
            PagedPoolCacheAligned,
            NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
            MaxPoolType,
            NonPagedPoolBase = 0,
            NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
            NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
            NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
            NonPagedPoolSession = 32,
            PagedPoolSession = NonPagedPoolSession + 1,
            NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
            DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
            NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
            PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
            NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
            NonPagedPoolNx = 512,
            NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
            NonPagedPoolSessionNx = NonPagedPoolNx + 32,
        }

        // API
        //=================================================
        
        [DllImport("ntdll.dll")]
        internal static extern UInt32 RtlGetVersion(
            ref OSVERSIONINFOEX VersionInformation);
        
        [DllImport("ntdll.dll")]
        internal static extern void RtlZeroMemory(
            IntPtr Destination,
            UInt32 length);
        
        [DllImport("ntdll.dll")]
        internal static extern UInt32 NtQueryObject(
            IntPtr objectHandle,
            OBJECT_INFORMATION_CLASS informationClass,
            IntPtr informationPtr,
            UInt32 informationLength,
            ref UInt32 returnLength);
        
        [DllImport("ntdll.dll")]
        internal static extern UInt32 NtQuerySystemInformation(
            UInt32 SystemInformationClass,
            IntPtr SystemInformation,
            UInt32 SystemInformationLength,
            ref UInt32 ReturnLength);
    }
}