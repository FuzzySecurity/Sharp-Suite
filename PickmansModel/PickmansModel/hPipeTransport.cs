using System;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;

namespace PickmansModel
{
	public class hPipeTransport
	{
		public static void initServerPipe(String sPipe, String sAES)
		{
			NamedPipeServerStream oPipe = new NamedPipeServerStream(sPipe, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message);
			Console.WriteLine("\n[?] Pipe open on : " + sPipe);

			oPipe.WaitForConnection();
			Console.WriteLine("\n[>] Client connected");

			// -= ECDH Key Exchange =-
			//-----------------------------
			ECDiffieHellmanCng server = hCrypto.initECDH();
			Console.WriteLine("[+] ECDiffieHellmanCng initialized..");
			Console.WriteLine("    |_ Hash Algorithm : " + server.HashAlgorithm);
			Console.WriteLine("    |_ Public Key : \n" + hPickman.HexDump(server.PublicKey.ToByteArray()));
			
			// Encrypt & Send data to client
			Byte[] bServerPub = hCrypto.toAES(sAES, server.PublicKey.ToByteArray());
			oPipe.Write(bServerPub, 0, bServerPub.Length);

			// Decrypt, Get client public key & derive secret
			hPickman.ECDH_SHARED_KEY_MAT oSessionKey = new hPickman.ECDH_SHARED_KEY_MAT();
			Byte[] bMessage = hPickman.ReadPipeMessage(oPipe);
			try
			{
				oSessionKey = hCrypto.deriveECDH(server, hCrypto.fromAES(sAES, bMessage));
			}
			catch (Exception ex)
			{
				Console.WriteLine("\n[!] Failed to decode client public key..");
				Console.WriteLine("    |_ " + ex.Message);
				return;
			}
			Console.WriteLine("[+] Received client ECDH public key");
			Console.WriteLine("    |_ AES Encrypted Public Key : \n" + hPickman.HexDump(bMessage));
			
			Console.WriteLine("[>] Derived Shared Secret");
			Console.WriteLine(hPickman.HexDump(oSessionKey.bDerivedKey));
			Console.WriteLine("[>] Derived Shared IV");
			Console.WriteLine(hPickman.HexDump(oSessionKey.bIV));
			
			// -= Connection Loop =-
			//-----------------------------
			// You can define a connection loop here if you like
			//while (true)
			//{
			//}
			
			// -= Send some text back and forth =-
			//-----------------------------
			
			// Read a client message
			bMessage = hPickman.ReadPipeMessage(oPipe);
			Byte[] bsMessage = hCrypto.fromAES(oSessionKey, bMessage);
			Console.WriteLine("[Client Received] : " + hPickman.UTF32ToString(bsMessage) + "\n");
			
			// Send a server message
			String sMessage = "You know, there are things that won’t do for Newbury Street—things that are out of place here, and that can’t be conceived here, anyhow. It’s my business to catch the overtones of the soul, and you won’t find those in a parvenu set of artificial streets on made land. Back Bay isn’t Boston—it isn’t anything yet, because it’s had no time to pick up memories and attract local spirits. If there are any ghosts here, they’re the tame ghosts of a salt marsh and a shallow cove; and I want human ghosts—the ghosts of beings highly organised enough to have looked on hell and known the meaning of what they saw.";
			Console.WriteLine("[Server Sending] : " + sMessage + "\n");
			Byte[] bChat = hPickman.StringToUTF32(sMessage);
			Byte[] bCrypt = hCrypto.toAES(oSessionKey, bChat);
			oPipe.Write(bCrypt, 0, bCrypt.Length);
			
			// Read a client message
			bMessage = hPickman.ReadPipeMessage(oPipe);
			bsMessage = hCrypto.fromAES(oSessionKey, bMessage);
			Console.WriteLine("[Client] : " + hPickman.UTF32ToString(bsMessage) + "\n");
		}
		
		public static void initClientPipe(String sPipe, String sAES, String sHost = "localhost")
		{
			NamedPipeClientStream oPipe = new NamedPipeClientStream(sHost, sPipe, PipeDirection.InOut);
			try
			{
				oPipe.Connect(500);
			}
			catch
			{
				Console.WriteLine("[!] Failed to connect to pipe..");
				return;
			}
			oPipe.ReadMode = PipeTransmissionMode.Message;
			Console.WriteLine("[?] Connected to pipe on : " + sPipe);

			// -= ECDH Key Exchange =-
			//-----------------------------
			ECDiffieHellmanCng client = hCrypto.initECDH();
			Console.WriteLine("[+] ECDiffieHellmanCng initialized..");
			Console.WriteLine("    |_ Hash Algorithm : " + client.HashAlgorithm);
			Console.WriteLine("    |_ Public Key : \n" + hPickman.HexDump(client.PublicKey.ToByteArray()));

			hPickman.ECDH_SHARED_KEY_MAT oSessionKey = new hPickman.ECDH_SHARED_KEY_MAT();
			Byte[] bMessage = hPickman.ReadPipeMessage(oPipe);
			try
			{
				oSessionKey = hCrypto.deriveECDH(client, hCrypto.fromAES(sAES, bMessage));
			}
			catch (Exception ex)
			{
				Console.WriteLine("\n[!] Failed to decode server public key..");
				Console.WriteLine("    |_ " + ex.Message);
				return;
			}
			Console.WriteLine("[+] Received server ECDH public key");
			Console.WriteLine("    |_ AES Encrypted Public Key : \n" + hPickman.HexDump(bMessage));
			
			Console.WriteLine("[>] Derived Shared Secret");
			Console.WriteLine(hPickman.HexDump(oSessionKey.bDerivedKey));
			Console.WriteLine("[>] Derived Shared IV");
			Console.WriteLine(hPickman.HexDump(oSessionKey.bIV));

			// Encrypt & Send data to server
			Byte[] bClientPub = hCrypto.toAES(sAES, client.PublicKey.ToByteArray());
			oPipe.Write(bClientPub, 0, bClientPub.Length);
			
			// -= Connection Loop =-
			//-----------------------------
			// You can define a connection loop here if you like
			//while (true)
			//{
			//}
			
			// -= Send some text back and forth =-
			//-----------------------------
			
			// Send a client message
			String sMessage = "Well, if you must hear it, I don’t know why you shouldn’t. Maybe you ought to, anyhow, for you kept writing me like a grieved parent when you heard I’d begun to cut the Art Club and keep away from Pickman.";
			Console.WriteLine("[Client sending] : " + sMessage + "\n");
			Byte[] bChat = hPickman.StringToUTF32(sMessage);
			Byte[] bCrypt = hCrypto.toAES(oSessionKey, bChat);
			oPipe.Write(bCrypt, 0, bCrypt.Length);
			
			// Read a server message
			bMessage = hPickman.ReadPipeMessage(oPipe);
			Byte[] bsMessage = hCrypto.fromAES(oSessionKey, bMessage);
			Console.WriteLine("[Server Received] : " + hPickman.UTF32ToString(bsMessage) + "\n");
			
			// Send a client message
			sMessage = "Pickman had promised to shew me the place, and heaven knows he had done it. He led me out of that tangle of alleys in another direction, it seems, for when we sighted a lamp post we were in a half-familiar street with monotonous rows of mingled tenement blocks and old houses. Charter Street, it turned out to be, but I was too flustered to notice just where we hit it.";
			Console.WriteLine("[Client Sending] : " + sMessage + "\n");
			bChat = hPickman.StringToUTF32(sMessage);
			bCrypt = hCrypto.toAES(oSessionKey, bChat);
			oPipe.Write(bCrypt, 0, bCrypt.Length);
		}
	}
}