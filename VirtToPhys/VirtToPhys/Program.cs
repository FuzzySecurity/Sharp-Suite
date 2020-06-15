using System;
using CommandLine;

namespace VirtToPhys
{
	class Program
	{
		class ArgOptions
		{
			[Option("l", "Load")]
			public Boolean Load { get; set; }

			[Option("u", "Unload")]
			public Boolean Unload { get; set; }

			[Option("v", "VirtToPhys")]
			public String VirtToPhys { get; set; }
		}

		static void Main(string[] args)
		{
			hSupp.PrintBanner();
			var ArgOptions = new ArgOptions();
			if (CommandLineParser.Default.ParseArguments(args, ArgOptions))
			{
				if (ArgOptions.Load || ArgOptions.Unload || !String.IsNullOrEmpty(ArgOptions.VirtToPhys))
				{
					if (ArgOptions.Load)
					{
						Wrapper.LoadMsIo();
					}
					else if (ArgOptions.Unload)
					{
						Wrapper.UnLoadMsIo();
					}
					else
					{
						Wrapper.TranslateVirtToPhys((IntPtr)Convert.ToInt64(ArgOptions.VirtToPhys, 16));
					}
				}
				else
				{
					hSupp.GetHelp();
				}

			}
			else
			{
				hSupp.GetHelp();
			}
		}
	}
}
