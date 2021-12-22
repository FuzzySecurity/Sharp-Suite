using System;
using CommandLine;

namespace PickmansModel
{
	internal class Program
	{
		//Byte[] bEnc = hPickman.toAES("IamThePass!", hPickman.StringToUTF32("Hello, this is a test!"));
		//Console.WriteLine("Got --> " + Convert.ToBase64String(bEnc));
		//
		//Byte[] bDec = hPickman.fromAES("IamThePass!", bEnc);
		//Console.WriteLine("Dec --> " + hPickman.UTF32ToString(bDec));
		
		// Args
		private class argOptions
		{
			[Option("h", "host")]
			public String sHost { get; set; }
			
			[Option("p", "pipe")]
			public String sPipe { get; set; }

			[Option("a", "aes")]
			public String sAES { get; set; }

			[Option("m", "message")]
			public String sMessage { get; set; }
			
			[Option("s", "server")]
			public Boolean bServer { get; set; }
		}
		
		public static void Main(string[] args)
		{
			argOptions argOptions = new argOptions();
			if (CommandLineParser.Default.ParseArguments(args, argOptions))
			{
				if (!String.IsNullOrEmpty(argOptions.sPipe) || !String.IsNullOrEmpty(argOptions.sAES) || !String.IsNullOrEmpty(argOptions.sMessage))
				{
					if (argOptions.bServer)
					{
						hPipeTransport.initServerPipe(argOptions.sPipe, argOptions.sAES);
					}
					else
					{
						if (!String.IsNullOrEmpty(argOptions.sHost))
						{
							hPipeTransport.initClientPipe(argOptions.sPipe, argOptions.sAES, argOptions.sHost);
						}
						else
						{
							hPipeTransport.initClientPipe(argOptions.sPipe, argOptions.sAES);
						}
					}
				}
			}
			else
			{
				Console.WriteLine("[!] Failed to parse args..");
			}
		}
	}
}