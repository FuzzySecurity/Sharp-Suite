using System;
using Console = Colorful.Console;
using McMaster.Extensions.CommandLineUtils;
using System.Drawing;

namespace Londor
{
	[SuppressDefaultHelpOption]
	class Program
	{
		[Option("-h|--help", CommandOptionType.NoValue)]
		public Boolean Help { get; }

		[Option("-t|--type", CommandOptionType.SingleValue)]
		public hFrida.RuntimeType rType { get; }

		[Option("-p|--path", CommandOptionType.SingleValue)]
		public String sPath { get; } = String.Empty;

		[Option("-o|--out", CommandOptionType.SingleValue)]
		public String sOut { get; } = String.Empty;

		[Option("-pid|--pid", CommandOptionType.SingleValue)]
		public UInt32 pPID { get; set; } = 0;

		[Option("-n|--name", CommandOptionType.SingleValue)]
		public String sName { get; } = String.Empty;

		[Option("-s|--start", CommandOptionType.SingleValue)]
		public String Start { get; } = String.Empty;

		[Option("-a|--args", CommandOptionType.SingleValue)]
		public String sArgs { get; } = String.Empty;

		static void Main(string[] args)
		{
			hFrida.PrintLogo();
			if (ArgumentEscaper.EscapeAndConcatenate(args).Length == 0)
			{
				hFrida.PrintHelp();
				return;
			}
			CommandLineApplication.Execute<Program>(args);
		}

		private void OnExecute()
		{
			if (Help)
			{
				hFrida.PrintHelp();
				return;
			}

			if (rType == hFrida.RuntimeType.Coverage)
			{
				if (pPID == 0 && Start == String.Empty && sName == String.Empty)
				{
					Console.WriteLine("[!] Missing argument PID (-pid|--pid) or binpath (-s|--start)", Color.Red);
				} else
				{
					if (sOut == String.Empty)
					{
						Console.WriteLine("[!] Output path not provided (-o|--out)", Color.Red);
					} else
					{
						if (pPID != 0)
						{
							hFrida.CoverageByID(pPID, String.Empty, sOut);
						} else if (sName != String.Empty)
						{
							hFrida.CoverageByID(0, sName, sOut);
						} else
						{
							hFrida.CoverageByStart(Start, sArgs, sOut);
						}
					}
				}
			} else if (rType == hFrida.RuntimeType.Script)
			{
				if (pPID == 0 && Start == String.Empty && sName == String.Empty)
				{
					Console.WriteLine("[!] Missing argument PID (-pid|--pid) or binpath (-s|--start)", Color.Red);
				} else
				{
					if (sPath == String.Empty)
					{
						Console.WriteLine("[!] Script path not provided (-p|--path)", Color.Red);
					} else
					{
						if (pPID != 0)
						{
							hFrida.ScriptByID(pPID, String.Empty, sPath);
						} else if (sName != String.Empty)
						{
							hFrida.ScriptByID(0, sName, sPath);
						} else
						{
							hFrida.ScriptByStart(Start, sArgs, sPath);
						}
					}
				}
			} else
			{
				Console.WriteLine("[!] Instrumentation type not provided (-t|--type)", Color.Red);
			}
		}
	}
}
