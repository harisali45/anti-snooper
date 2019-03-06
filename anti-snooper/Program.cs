using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpPcap;
using PacketDotNet;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Diagnostics;
using System.IO;
namespace antiSnooper
{
    class Program
    {
        static string name = "antiSnooper";
        //MAC address of the gateway
        PhysicalAddress macOfGateway;
        //IP address of gateway
        IPAddress ipOfGateway;
        //the interface which is live
        SharpPcap.LibPcap.LibPcapLiveDevice liveInterface;
        //local machine's IP address
        String localIp;
        //Information about the process to run every interval
        ProcessStartInfo myProcess;
        delegate void temp();
        static void Main(string[] args)
        {
            Console.WriteLine(name+" is starting....");
            Program prog = new Program();
            //get MAC address of gateway
            if (!prog.IsNetworkAvailable() || !prog.findMACofGateway())
            {
                Console.WriteLine("No network detected. Press any key to exit");
                Console.ReadKey(true);
                return;
            }
            Console.WriteLine("antiSnooper is running. Press q anytime stop and quit");
            Timer timer = new Timer(prog.checkForAttack,null,1000,1000);
            while(true)
                if(Console.ReadKey(true).KeyChar=='q')
                    return;
        }
        public Program()
        {
            //initialize information about the process which runs every second
            myProcess = new ProcessStartInfo();
            //give name of the command to execute
            myProcess.FileName = "arp";
            //supply argments
            myProcess.Arguments = "-a";
            //specify that no window is needed
            myProcess.CreateNoWindow = true;
            myProcess.WindowStyle = ProcessWindowStyle.Hidden;
            myProcess.UseShellExecute = false;
            myProcess.RedirectStandardOutput = true;
        }
        /// <summary>
        /// Indicates whether any network connection is available.
        /// It does not check for virtual PCs.
        /// </summary>
        /// <returns>
        ///     <c>true</c> if a network connection is available; otherwise, <c>false</c>.
        /// </returns>
        protected bool IsNetworkAvailable()
        {
            if (!NetworkInterface.GetIsNetworkAvailable())
                return false;
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                // discard virtual cards
                if ((ni.Description.IndexOf("virtual", StringComparison.OrdinalIgnoreCase) >= 0) || (ni.Name.IndexOf("virtual", StringComparison.OrdinalIgnoreCase) >= 0))
                    continue;

                // if the interface is not working, or is a loopback adapter or uses tunnel connection, discard
                if ((ni.OperationalStatus != OperationalStatus.Up) || (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) ||
                    (ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel))
                    continue;

                // discard "Microsoft Loopback Adapter", it will not show as NetworkInterfaceType.Loopback
                //hence the string comparison
                if (ni.Description.Equals("Microsoft Loopback Adapter", StringComparison.OrdinalIgnoreCase))
                    continue;

                //get the ip of the gateway and store it in ipOfGateway
                ipOfGateway=ni.GetIPProperties().GatewayAddresses.FirstOrDefault<GatewayIPAddressInformation>().Address;
                
                //get local machine's IP
                IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
                foreach (IPAddress ip in host.AddressList)
                    if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        localIp = ip.ToString();
                Console.WriteLine("Local machine's IP: "+localIp);
                Console.WriteLine("IP of gateway: "+ipOfGateway.ToString());
                return true;
            }
            return false;
        }
        /// <summary>
        /// Finds MAC address of the gateway, when its IP address is in ipOfgateway.
        /// The MAC address is stored in macOfGateway.
        /// </summary>
        /// <returns>
        ///     <c>true</c> if MAC address is found, otherwise <c>false</c>.
        /// </returns>
        protected bool findMACofGateway()
        {
            ARP arp;
            if (ipOfGateway == null)
                return false;
            //get list of all available interfaces
            SharpPcap.LibPcap.LibPcapLiveDeviceList lldl = SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance;
            //find MAC address of gateway
            foreach (SharpPcap.LibPcap.LibPcapLiveDevice lld in lldl)
            {
                arp = new ARP(lld);
                try
                {
                    macOfGateway = arp.Resolve(ipOfGateway);
                    Console.WriteLine("MAC of gateway: "+macOfGateway.ToString());
                    liveInterface = lld;
                }
                catch (NullReferenceException)
                {
                    continue;
                }
                return true;
            }
            return false;
        }
        /// <summary>
        /// This method checks whether MAC address of gateway has changed.
        /// If so, it invokes correctMac() function to correct it
        /// </summary>
        protected void checkForAttack(object o)
        {
            //start the process
            Process p = Process.Start(myProcess);
            //get the OutputStream of the process
            StreamReader sr = p.StandardOutput;
            //skip first three lines
            for (int i = 0; i < 2; i++)
                sr.ReadLine();
            //now read all lines and search for gateway's IP
            while (!sr.EndOfStream)
            {
                String line = sr.ReadLine().Trim();
                //remove unnecessary spaces
                while (line.Contains("  "))
                    line.Replace("  "," ");
                /*At this point, there is a single space between all words in line*/
                String[] parts = line.Split(' ');
                if (parts[0].Trim() == ipOfGateway.ToString())
                {
                    //check if ARP poisoning has been performed
                    if (parts[1].Replace("-","").ToUpper().Trim() != macOfGateway.ToString())
                        correctMac();
                    break;
                }
            }
            sr.Close();
        }
        /// <summary>
        /// This method is called whenever a change in MAC address of gateway is detected.
        /// It reverts the MAC address back to the previous address.
        /// </summary>
        protected void correctMac()
        {
            //construct a new ethernet packet
            EthernetPacket ep = new EthernetPacket(macOfGateway, liveInterface.Addresses[1].Addr.hardwareAddress,EthernetPacketType.Arp);
            //construct a new ARP packet
            ARPPacket arp = new ARPPacket(ARPOperation.Response, liveInterface.Addresses[1].Addr.hardwareAddress, IPAddress.Parse(localIp),macOfGateway,ipOfGateway);
            //insert arp packet in ethernet packet
            ep.PayloadPacket=arp;
            //send the ethernet packet
            liveInterface.SendPacket(ep);
        }
    }
}