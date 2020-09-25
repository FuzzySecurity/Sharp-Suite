using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;

namespace GetNetworkInterfaces
{
    class Program
    {
        public static void GetMyInterfaces()
        {
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in adapters)
            {
                IPInterfaceProperties properties = adapter.GetIPProperties();
                Console.WriteLine("\n" + adapter.Description);
                Console.WriteLine("  Name .................................... : {0}", adapter.Name);
                Console.WriteLine("  Interface type .......................... : {0}", adapter.NetworkInterfaceType);
                Console.WriteLine("  Physical Address ........................ : {0}", adapter.GetPhysicalAddress().ToString());
                Console.WriteLine("  Operational status ...................... : {0}", adapter.OperationalStatus);

                string versions = "";
                if (adapter.Supports(NetworkInterfaceComponent.IPv4))
                {
                    versions = "IPv4";
                }
                if (adapter.Supports(NetworkInterfaceComponent.IPv6))
                {
                    if (versions.Length > 0)
                    {
                        versions += " ";
                    }
                    versions += "IPv6";
                }
                Console.WriteLine("  IP version .............................. : {0}", versions);

                // Get IP
                foreach (UnicastIPAddressInformation ip in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        Console.WriteLine("  IPv4 .................................... : {0}", ip.Address.ToString());
                        Console.WriteLine("  Mask .................................... : {0}", ip.IPv4Mask);
                        IPv4InterfaceProperties iProp = adapter.GetIPProperties().GetIPv4Properties();
                        try
                        {
                            Console.WriteLine("  DHCP .................................... : {0}", iProp.IsDhcpEnabled);
                        } catch { }
                    }

                    if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    {
                        Console.WriteLine("  IPv6 .................................... : {0}", ip.Address.ToString());
                    }
                }

                IPInterfaceProperties iip = adapter.GetIPProperties();
                GatewayIPAddressInformationCollection giaic =  iip.GatewayAddresses;
                if (giaic.Count > 0) {
                    if (giaic.First().Address.AddressFamily.ToString() == "InterNetwork")
                    {
                        Console.WriteLine("  Default Gateway ......................... : {0}", giaic.First().Address);
                    }
                }

                IPAddressCollection iac = adapter.GetIPProperties().DhcpServerAddresses;
                if (iac.Count > 0)
                {
                    foreach (IPAddress ia in iac)
                    {
                        if (ia.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            Console.WriteLine("  DHCP Server ............................. : {0}", ia.MapToIPv4().ToString());
                        }

                        if (ia.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            Console.WriteLine("  DHCP Server ............................. : {0}", ia.MapToIPv6().ToString());
                        }
                    }
                }

                IPAddressCollection iacd = adapter.GetIPProperties().DnsAddresses;
                if (iacd.Count > 0)
                {
                    foreach (IPAddress ia in iacd)
                    {
                        if (ia.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            Console.WriteLine("  DNS Server .............................. : {0}", ia.MapToIPv4().ToString());
                        }

                        if (ia.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                        {
                            Console.WriteLine("  DNS Server .............................. : {0}", ia.MapToIPv6().ToString());
                        }
                    }
                }
                Console.WriteLine("  Dynamic DNS ............................. : {0}", iip.IsDynamicDnsEnabled);
                Console.WriteLine("  DNS suffix .............................. : {0}", properties.DnsSuffix);
                Console.WriteLine("  DNS enabled ............................. : {0}", properties.IsDnsEnabled);

                if (adapter.Supports(NetworkInterfaceComponent.IPv4))
                {
                    IPv4InterfaceProperties ipv4 = properties.GetIPv4Properties();
                    if (ipv4.UsesWins)
                    {
                        IPAddressCollection winsServers = properties.WinsServersAddresses;
                        if (winsServers.Count > 0)
                        {
                            Console.WriteLine("  Primary WINS Server ..................... : {0}", winsServers.First().MapToIPv4().ToString());
                        }
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            GetMyInterfaces();
        }
    }
}
