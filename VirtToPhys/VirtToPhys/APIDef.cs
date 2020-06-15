using System;
using System.Runtime.InteropServices;

namespace VirtToPhys
{
	class APIDef
	{
		// MSIO IOCTL's
		//===========================
		public static UInt32 IOCTL_MSIO_MAPPHYSTOLIN = 0x80102040;
		public static UInt32 IOCTL_MSIO_UNMAPPHYSADDR = 0x80102044;

		// Constants
		//===========================
		public static UInt32 NTSTATUS_STATUS_SUCCESS = 0x0;
		public static UInt32 NTSTATUS_STATUS_ACCESS_DENIED = 0xC0000022;
		public static UInt32 NTSTATUS_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
		public static UInt32 NTSTATUS_STATUS_NOT_ALL_ASSIGNED = 0x00000106;
		public static UInt32 NTSTATUS_STATUS_PRIVILEGE_NOT_HELD = 0xC0000061;
		public static UInt32 NTSTATUS_STATUS_BUFFER_TOO_SMALL = 0xC0000023;
		public static UInt32 NTSTATUS_STATUS_MORE_ENTRIES = 0x00000105;

		public static UInt64 PHY_ADDRESS_MASK = 0x000ffffffffff000;
		public static UInt64 PHY_ADDRESS_MASK_2MB_PAGES = 0x000fffffffe00000;
		public static UInt64 VADDR_ADDRESS_MASK_2MB_PAGES = 0x00000000001fffff;
		public static UInt64 VADDR_ADDRESS_MASK_4KB_PAGES = 0x0000000000000fff;
		public static UInt16 ENTRY_PRESENT_BIT = 1;
		public static UInt64 ENTRY_PAGE_SIZE_BIT = 0x0000000000000080;

		public static UInt32 TOKEN_ADJUST_PRIVILEGES = 0x20;
		public static UInt32 TOKEN_QUERY = 0x8;

		public static UInt32 SE_PRIVILEGE_ENABLED = 0x2;
		public static UInt32 SE_DEBUG_PRIVILEGE = 20;
		public static UInt32 SE_LOAD_DRIVER_PRIVILEGE = 10;

		public static UInt32 SERVICE_ERROR_NORMAL = 0x00000001;
		public static UInt32 SERVICE_KERNEL_DRIVER = 0x00000001;
		public static UInt32 SERVICE_DEMAND_START = 0x00000003;

		// Enums
		//===========================
		public enum FileAccessFlags : UInt32
		{
			DELETE = 0x00010000,
			READ_CONTROL = 0x00020000,
			WRITE_DAC = 0x00040000,
			WRITE_OWNER = 0x00080000,
			SYNCHRONIZE = 0x00100000,
			STANDARD_RIGHTS_REQUIRED = 0x000F0000,
			STANDARD_RIGHTS_READ = READ_CONTROL,
			STANDARD_RIGHTS_WRITE = READ_CONTROL,
			STANDARD_RIGHTS_EXECUTE = READ_CONTROL,
			FILE_READ_DATA = 0x0001,
			FILE_LIST_DIRECTORY = 0x0001,
			FILE_WRITE_DATA = 0x0002,
			FILE_ADD_FILE = 0x0002,
			FILE_APPEND_DATA = 0x0004,
			FILE_ADD_SUBDIRECTORY = 0x0004,
			FILE_CREATE_PIPE_INSTANCE = 0x0004,
			FILE_READ_EA = 0x0008,
			FILE_WRITE_EA = 0x0010,
			FILE_EXECUTE = 0x0020,
			FILE_TRAVERSE = 0x0020,
			FILE_DELETE_CHILD = 0x0040,
			FILE_READ_ATTRIBUTES = 0x0080,
			FILE_WRITE_ATTRIBUTES = 0x0100,
			FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF,
			FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
			FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE,
			FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE
		}

		// API Structs
		//===========================
		public struct LUID
		{
			public UInt32 LowPart;
			public Int32 HighPart;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct LUID_AND_ATTRIBUTES
		{
			public LUID Luid;
			public UInt32 Attributes;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct TOKEN_PRIVILEGES
		{
			public UInt32 PrivilegeCount;
			public LUID_AND_ATTRIBUTES Privileges;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct UNICODE_STRING
		{
			public UInt16 Length;
			public UInt16 MaximumLength;
			public IntPtr Buffer;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 0)]
		public struct OBJECT_ATTRIBUTES
		{
			public Int32 Length;
			public IntPtr RootDirectory;
			public IntPtr ObjectName; // -> UNICODE_STRING
			public uint Attributes;
			public IntPtr SecurityDescriptor;
			public IntPtr SecurityQualityOfService;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct OBJECT_DIRECTORY_INFORMATION
		{
			public UNICODE_STRING Name;
			public UNICODE_STRING TypeName;
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct IO_STATUS_BLOCK
		{
			public IntPtr Status;
			public IntPtr Information;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 16)]
		public struct MSIO_PHYSICAL_MEMORY_INFO
		{
			public UIntPtr ViewSize;
			public IntPtr BusAddress;
			public IntPtr SectionHandle;
			public IntPtr BaseAddess;
			public IntPtr ReferenceObject;
		}

		// API's
		//===========================
		[DllImport("ntdll.dll")]
		public static extern UInt32 NtOpenProcessToken(
			IntPtr ProcessHandle,
			UInt32 DesiredAccess,
			ref IntPtr TokenHandle);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtAdjustPrivilegesToken(
			IntPtr TokenHandle,
			Boolean DisableAllPrivileges,
			ref TOKEN_PRIVILEGES NewState,
			UInt32 BufferLength,
			IntPtr PreviousState,
			ref UInt32 ReturnLength);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtClose(
			IntPtr Handle);

		[DllImport("ntdll.dll")]
		public static extern void RtlInitUnicodeString(
			ref UNICODE_STRING DestinationString,
			[MarshalAs(UnmanagedType.LPWStr)]
			string SourceString);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtOpenDirectoryObject(
			ref IntPtr DirectoryHandle,
			UInt32 DesiredAccess,
			ref OBJECT_ATTRIBUTES ObjectAttributes);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtQueryDirectoryObject(
			IntPtr DirectoryHandle,
			IntPtr Buffer,
			UInt32 Length,
			Boolean ReturnSingleEntry,
			Boolean RestartScan,
			ref UInt32 Context,
			ref UInt32 ReturnLength);

		[DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
		public static extern Boolean RtlDosPathNameToRelativeNtPathName_U(
			String DosFileName,
			ref UNICODE_STRING NtFileName,
			IntPtr FilePart,
			IntPtr Reserved);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtLoadDriver(
			ref UNICODE_STRING DriverServiceName);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtUnloadDriver(
			ref UNICODE_STRING DriverServiceName);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtCreateFile(
			ref IntPtr FileHandle,
			UInt32 DesiredAccess,
			ref OBJECT_ATTRIBUTES ObjectAttributes,
			ref IO_STATUS_BLOCK IoStatusBlock,
			IntPtr AllocationSize,
			uint FileAttributes,
			uint ShareAccess,
			uint CreateDisposition,
			uint CreateOptions,
			IntPtr EaBuffer,
			uint EaLength);

		[DllImport("ntdll.dll")]
		public static extern void RtlZeroMemory(
			IntPtr Destination,
			int length);

		[DllImport("ntdll.dll")]
		public static extern UInt32 NtDeviceIoControlFile(
			IntPtr FileHandle,
			IntPtr Event,
			IntPtr ApcRoutine,
			IntPtr ApcContext,
			ref IO_STATUS_BLOCK IoStatusBlock,
			UInt32 IoControlCode,
			IntPtr InputBuffer,
			UInt32 InputBufferLength,
			IntPtr OutputBuffer,
			UInt32 OutputBufferLength);
	}
}
