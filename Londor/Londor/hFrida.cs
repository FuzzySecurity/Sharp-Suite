using System;
using System.Collections.Generic;
using Console = Colorful.Console;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Frida;
using Newtonsoft.Json;
using System.Drawing;

namespace Londor
{
	class hFrida
	{
		// ASCII & help
		//---------------------------------

		// This palette is bugged across cmd/PS/terminal
		// I wanted to fix it but I figured it actually
		// looks ok the way it is.. ¯\_(ツ)_/¯
		public static void PrintLogo()
		{
			Color oldColor = Console.ForegroundColor;
			String sLondor = "    __              _         \n" +
							 "   |  |   ___ ___ _| |___ ___ \n" +
							 "   |  |__| . |   | . | . |  _|\n" +
							 "   |_____|___|_|_|___|___|_|  \n";
			Console.WriteWithGradient(sLondor.ToCharArray(), Color.Yellow, Color.Fuchsia, 6);
			Colorful.Console.ReplaceAllColorsWithDefaults();
			Console.WriteLine("\n                         ~b33f\n\n");
		}

		public static void PrintHelp()
		{
			string HelpText = "  >--~~--> Args? <--~~--<\n\n" +
							  " --help   (-h)    Show this help message.\n" +
							  " --type   (-t)    Instrumentation type: Coverage, Script.\n" +
							  " --out    (-o)    Full output path for DRCOV file.\n" +
							  " --path   (-p)    Full path to JS script.\n" +
							  " --pid    (-pid)  PID of the process to attach to.\n" +
							  " --name   (-n)    Substring name of process to attach to.\n" +
							  " --start  (-s)    Full path to binary to launch.\n" +
							  " --args   (-a)    Args to pass to binary.\n\n" +
							  "  >--~~--> Usage? <--~~--<\n\n";
			Console.WriteLine(HelpText);
			Console.WriteLine(" # Generate coverage information for a process", Color.LightGreen);
			Console.WriteLine(" Londor.exe -t Coverage -pid 123 -o C:\\Some\\Out\\Path.drcov", Color.FromArgb(230, 230, 230));
			Console.WriteLine(" Londor.exe -t Coverage -n notepad -o C:\\Some\\Out\\Path.drcov", Color.FromArgb(230, 230, 230));
			Console.WriteLine(" Londor.exe -t Coverage -s C:\\Some\\Proc\\bin.exe -a SomeOrNoArgs -o C:\\Some\\Out\\Path.drcov\n", Color.FromArgb(230, 230, 230));
			Console.WriteLine(" # Inject JS script into process", Color.LightGreen);
			Console.WriteLine(" Londor.exe -t Script -pid 123 -p C:\\Some\\Path\\To\\Script.js", Color.FromArgb(230, 230, 230));
			Console.WriteLine(" Londor.exe -t Script -n notepad -p C:\\Some\\Path\\To\\Script.js", Color.FromArgb(230, 230, 230));
			Console.WriteLine(" Londor.exe -t Script -s C:\\Some\\Proc\\bin.exe -a SomeOrNoArgs -p C:\\Some\\Path\\To\\Script.js\n", Color.FromArgb(230, 230, 230));
		}

		// Globals
		//---------------------------------
		public static String OutputPath = String.Empty;
		public static Byte[] BBTableArray = { };
		public static UInt64 BBTableCount = 0;
		public static Script fScript;
		public static readonly object FileWriteLock = new object();

		// Enums & Structs
		//---------------------------------
		public enum RuntimeType
		{
			None = 0,
			Coverage,
			Script
		}

		public class FridaMessage
		{
			[JsonProperty("type")]
			public String Type { get; set; }
			[JsonProperty("payload")]
			public String Payload { get; set; }
		}

		// Helpers
		//---------------------------------
		public static Device GetLocalDevice()
		{
			DeviceManager dm = new DeviceManager(System.Windows.Threading.Dispatcher.CurrentDispatcher);
			Device[] devices = dm.EnumerateDevices();
			foreach (Device d in devices)
			{
				if (d.Id == "local")
				{
					return d;
				}
			}

			// Local is always valid
			return null;
		}

		public static Process GetProcessFromDevice(Device d, UInt32 procId = 0, String procName = "")
		{
			Process[] aProc = d.EnumerateProcesses();
			List<Process> aResults = new List<Process>();
			foreach (Process p in aProc)
			{
				if (procId != 0)
				{
					if (p.Pid == procId)
					{
						aResults.Add(p);
					}
				} else
				{
					if (p.Name.IndexOf(procName, StringComparison.CurrentCultureIgnoreCase) >= 0)
					{
						aResults.Add(p);
					}
				}
			}

			if (aResults.Count == 0)
			{
				Console.WriteLine("[!] Specified process not found..", Color.Red);
				return null;
			} else if (aResults.Count > 1)
			{
				Console.WriteLine("[!] Ambiguous process match..", Color.Red);
				foreach (Process p in aResults)
				{
					Console.WriteLine("    |-> PID: " + p.Pid + "; Name: " + p.Name, Color.Red);
				}
				return null;
			} else
			{
				return aResults.First();
			}
		}

		public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
		{
			var isInRoleWithAccess = false;

			try
			{
				var di = new DirectoryInfo(DirectoryPath);
				var acl = di.GetAccessControl();
				var rules = acl.GetAccessRules(true, true, typeof(NTAccount));
				var currentUser = WindowsIdentity.GetCurrent();
				var principal = new WindowsPrincipal(currentUser);
				foreach (AuthorizationRule rule in rules)
				{
					var fsAccessRule = rule as FileSystemAccessRule;
					if (fsAccessRule == null)
						continue;

					if ((fsAccessRule.FileSystemRights & AccessRight) > 0)
					{
						var ntAccount = rule.IdentityReference as NTAccount;
						if (ntAccount == null)
							continue;

						if (principal.IsInRole(ntAccount.Value))
						{
							if (fsAccessRule.AccessControlType == AccessControlType.Deny)
								return false;
							isInRoleWithAccess = true;
						}
					}
				}
			}
			catch (UnauthorizedAccessException)
			{
				return false;
			}
			return isInRoleWithAccess;
		}

		public static Boolean IsValidOutPath(String Path)
		{
			try
			{
				FileAttributes CheckAttrib = File.GetAttributes(Path);
				if (CheckAttrib.HasFlag(FileAttributes.Directory))
				{
					Console.WriteLine("[!] Specify an output filepath not a directory (-o|--out)", Color.Red);
					return false;
				}
			} catch { }

			if (!(Directory.Exists(System.IO.Path.GetDirectoryName(Path))))
			{
				Console.WriteLine("[!] Invalid path specified (-o|--out)", Color.Red);
				return false;
			}

			if (!(DirectoryHasPermission(System.IO.Path.GetDirectoryName(Path), FileSystemRights.Write)))
			{
				Console.WriteLine("[!] No write access to output path (-o|--out)", Color.Red);
				return false;
			}

			return true;
		}

		public static void FileWriteWrapper(String inputText, Byte[] inputBytes, String path)
		{
			if (!String.IsNullOrEmpty(inputText))
			{
				if (!File.Exists(path))
				{
					File.WriteAllText(path, inputText);
				}
				else
				{
					File.AppendAllText(path, inputText);
				}
			} else
			{
				using (var stream = new FileStream(path, FileMode.Append))
				{
					stream.Write(inputBytes, 0, inputBytes.Length);
				}
			}
		}

		public static void msg_script(object sender, Frida.ScriptMessageEventArgs e)
		{
			// For script payloads we only care about message content, not data
			// |-> Deserialize JSON message
			FridaMessage messageContent = JsonConvert.DeserializeObject<FridaMessage>(e.Message);
			if (messageContent.Type == "send")
			{
				if (!String.IsNullOrEmpty(messageContent.Payload))
				{
					Console.WriteLine(messageContent.Payload, Color.FromArgb(0, 255, 255));
				}
			} else
			{
				Console.WriteLine("[!] Runtime error: " + messageContent.Payload, Color.FromArgb(255, 153, 153));
			}
		}

		public static void msg_coverage(object sender, Frida.ScriptMessageEventArgs e)
		{
			lock (FileWriteLock)
			{
				// For coverage we use both messages and data
				// |-> Deserialize JSON message
				FridaMessage messageContent = JsonConvert.DeserializeObject<FridaMessage>(e.Message);
				if (messageContent.Type == "send")
				{
					if (!String.IsNullOrEmpty(messageContent.Payload))
					{
						FileWriteWrapper(messageContent.Payload, null, OutputPath);
					}
				}
				else
				{
					Console.WriteLine("[!] Runtime error: " + messageContent.Payload, Color.FromArgb(255, 153, 153));
				}

				// Handle data
				if (e.Data != null)
				{
					BBTableCount += (UInt64)(e.Data.Length/8);
					Console.WriteLine("[+] Block trace Length: " + e.Data.Length, Color.FromArgb(0, 255, 255));
					Console.WriteLine("    |-> BBS slice: " + (e.Data.Length / 8) + "; Total BBS: " + BBTableCount, Color.FromArgb(0, 255, 255));

					// Concat byte array
					BBTableArray = BBTableArray.Concat(e.Data).ToArray();
				}
			}
		}

		public static void detatch_coverage()
		{
			Console.WriteLine("\n[?] Unloading hooks, please wait..", Color.Yellow);
			fScript.Unload();
			String sTableHead = "BB Table: " + BBTableCount + " bbs\n";
			FileWriteWrapper(sTableHead, null, OutputPath);
			FileWriteWrapper(String.Empty, BBTableArray, OutputPath);
			Console.WriteLine("    |-> Wrote trace data to file", Color.Yellow);
		}

		public static void detatch_generic()
		{
			Console.WriteLine("\n[?] Unloading hooks, please wait..", Color.Yellow);
			fScript.Unload();
		}

		public static void fridaOnDetatchHandler(object sender, Frida.SessionDetachedEventArgs e)
		{
			// If we are doing coverage, finish writing coverage file
			if (BBTableCount != 0)
			{
				String sTableHead = "BB Table: " + BBTableCount + " bbs\n";
				FileWriteWrapper(sTableHead, null, OutputPath);
				FileWriteWrapper(String.Empty, BBTableArray, OutputPath);
			}
			Console.WriteLine("\n[+] Exit Reason: " + e.Reason, Color.Yellow);
			if (BBTableCount != 0)
			{
				Console.WriteLine("    |-> Wrote partial trace data to file..", Color.Yellow);
			}
			System.Windows.Threading.Dispatcher.ExitAllFrames();
		}

		public static void InjectRunningProcess(Device dev, UInt32 procID, String scriptText, RuntimeType rType)
		{
			Session context = dev.Attach(procID);
			context.Detached += new SessionDetachedHandler(fridaOnDetatchHandler);
			try
			{
				fScript = context.CreateScript(scriptText);
				if (rType == RuntimeType.Script) // Regular script
				{
					fScript.Message += new Frida.ScriptMessageHandler(msg_script);
					Console.CancelKeyPress += delegate { detatch_generic(); };
				} else // Call trace
				{
					fScript.Message += new Frida.ScriptMessageHandler(msg_coverage);
					Console.CancelKeyPress += delegate { detatch_coverage(); };
				}

				fScript.Load();
				// We can only try/catch here, there is
				// no way to tell if a proc is suspended
				try
				{
					dev.Resume(procID);
				} catch { }
				Console.WriteLine("    |-> Script loaded\n", Color.White);
				Console.WriteLine("[*] Press ctrl-c to detach..\n", Color.Yellow);
				System.Windows.Threading.Dispatcher.Run();
			}
			catch (Exception ex)
			{
				Console.WriteLine("[!] Error loading script!", Color.Red);
				Console.WriteLine(ex.ToString());
				return;
			}
		}

		// Wrap
		//---------------------------------
		public static void CoverageByID(UInt32 ProcID, String ProcName, String OutPath)
		{
			// Print status
			Console.WriteLine("[>] Getting coverage for PID..", Color.White);

			// Validate outpath
			if (!IsValidOutPath(OutPath))
			{
				return;
			} else
			{
				OutputPath = OutPath;
			}

			// Get local device
			Device local = GetLocalDevice();
			Process pr = null;
			if (ProcID != 0)
			{
				pr = hFrida.GetProcessFromDevice(local, ProcID, String.Empty);
			} else
			{
				pr = hFrida.GetProcessFromDevice(local, 0, ProcName);
			}

			if (pr == null)
			{
				return;
			} else
			{
				Console.WriteLine("    |-> PID: " + pr.Pid + "; Name: " + pr.Name, Color.White);
			}

			// Get coverage script
			String scriptBody = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(FridaScript.coverage));

			// Inject
			InjectRunningProcess(local, pr.Pid, scriptBody, RuntimeType.Coverage);
		}

		public static void CoverageByStart(String BinPath, String ProcArgs, String OutPath)
		{
			// Print status
			Console.WriteLine("[>] Spawning process for coverage..", Color.White);

			// Validate outpath
			if (!IsValidOutPath(OutPath))
			{
				return;
			}
			else
			{
				OutputPath = OutPath;
			}

			// Get local device
			Device local = GetLocalDevice();
			UInt32 procID = 0;
			if (ProcArgs == String.Empty)
			{
				procID = local.Spawn(BinPath, null, null, null, null);
			} else
			{
				procID = local.Spawn(BinPath, new string[] { BinPath, ProcArgs }, null, null, null);
			}

			if (procID == 0)
			{
				return;
			}
			else
			{
				Console.WriteLine("    |-> PID: " + procID + "; Path: " + BinPath, Color.White);
			}

			// Get coverage script
			String scriptBody = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(FridaScript.coverage));

			// Inject
			InjectRunningProcess(local, procID, scriptBody, RuntimeType.Coverage);
		}

		public static void ScriptByID(UInt32 ProcID, String ProcName, String Path)
		{
			// Print status
			Console.WriteLine("[>] Injecting JS into PID..", Color.White);

			if (!File.Exists(Path))
			{
				Console.WriteLine("[!] Invalid script path specified (-p|--path)", Color.Red);
				return;
			}

			// Get local device
			Device local = GetLocalDevice();
			Process pr = null;
			if (ProcID != 0)
			{
				pr = hFrida.GetProcessFromDevice(local, ProcID, String.Empty);
			}
			else
			{
				pr = hFrida.GetProcessFromDevice(local, 0, ProcName);
			}

			if (pr == null)
			{
				return;
			}
			else
			{
				Console.WriteLine("    |-> PID: " + pr.Pid + "; Name: " + pr.Name, Color.White);
			}

			// Get script content
			String scriptBody = String.Empty;
			try
			{
				scriptBody = File.ReadAllText(Path);
			} catch
			{
				Console.WriteLine("[!] Failed to read script file (-p|--path)", Color.Red);
				return;
			}

			// Inject
			InjectRunningProcess(local, pr.Pid, scriptBody, RuntimeType.Script);
		}

		public static void ScriptByStart(String BinPath, String ProcArgs, String Path)
		{
			// Print status
			Console.WriteLine("[>] Spawning process to inject JS..", Color.White);

			if (!File.Exists(Path))
			{
				Console.WriteLine("[!] Invalid script path specified (-p|--path)", Color.Red);
				return;
			}

			// Get local device
			Device local = GetLocalDevice();
			UInt32 procID = 0;
			if (ProcArgs == String.Empty)
			{
				procID = local.Spawn(BinPath, null, null, null, null);
			}
			else
			{
				procID = local.Spawn(BinPath, new string[] { BinPath, ProcArgs }, null, null, null);
			}

			if (procID == 0)
			{
				return;
			}
			else
			{
				Console.WriteLine("    |-> PID: " + procID + "; Path: " + BinPath, Color.White);
			}

			// Get script content
			String scriptBody = String.Empty;
			try
			{
				scriptBody = File.ReadAllText(Path);
			}
			catch
			{
				Console.WriteLine("[!] Failed to read script file (-p|--path)", Color.Red);
				return;
			}

			// Inject
			InjectRunningProcess(local, procID, scriptBody, RuntimeType.Script);
		}
	}
}
