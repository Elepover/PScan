using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Threading;
using static PScan.Types;

namespace PScan {
    /// <summary>
    /// via https://stackoverflow.com/questions/4172677/c-enumerate-ip-addresses-in-a-range
    /// </summary>
    public class IPRange
    {
        public IPRange(string ipRange)
        {
            if (ipRange == null)
                throw new ArgumentNullException();

            if (!TryParseCIDRNotation(ipRange) && !TryParseSimpleRange(ipRange))
                throw new ArgumentException();
        }

        public IEnumerable<IPAddress> GetAllIP()
        {
            int capacity = 1;
            for (int i = 0; i < 4; i++)
                capacity *= endIP[i] - beginIP[i] + 1;

            List<IPAddress> ips = new List<IPAddress>(capacity);
            for (int i0 = beginIP[0]; i0 <= endIP[0]; i0++)
            {
                for (int i1 = beginIP[1]; i1 <= endIP[1]; i1++)
                {
                    for (int i2 = beginIP[2]; i2 <= endIP[2]; i2++)
                    {
                        for (int i3 = beginIP[3]; i3 <= endIP[3]; i3++)
                        {
                            ips.Add(new IPAddress(new byte[] { (byte)i0, (byte)i1, (byte)i2, (byte)i3 }));
                        }
                    }
                }
            }

            return  ips;
        }

        /// <summary>
        /// Parse IP-range string in CIDR notation.
        /// For example "12.15.0.0/16".
        /// </summary>
        /// <param name="ipRange"></param>
        /// <returns></returns>
        private bool TryParseCIDRNotation(string ipRange)
        {
            string[] x = ipRange.Split('/');

            if (x.Length != 2)
                return false;

            byte bits = byte.Parse(x[1]);
            uint ip = 0;
            String[] ipParts0 = x[0].Split('.');
            for (int i = 0; i < 4; i++)
            {
                ip = ip << 8;
                ip += uint.Parse(ipParts0[i]);
            }

            byte shiftBits = (byte)(32 - bits);
            uint ip1 = (ip >> shiftBits) << shiftBits;

            if (ip1 != ip) // Check correct subnet address
                return false;

            uint ip2 = ip1 >> shiftBits;
            for (int k = 0; k < shiftBits; k++)
            {
                ip2 = (ip2 << 1) + 1;
            }

            beginIP = new byte[4];
            endIP = new byte[4];

            for (int i = 0; i < 4; i++)
            {
                beginIP[i] = (byte) ((ip1 >> (3 - i) * 8) & 255);
                endIP[i] = (byte)((ip2 >> (3 - i) * 8) & 255);
            }

            return true;
        }

        /// <summary>
        /// Parse IP-range string "12.15-16.1-30.10-255"
        /// </summary>
        /// <param name="ipRange"></param>
        /// <returns></returns>
        private bool TryParseSimpleRange(string ipRange)
        {
            String[] ipParts = ipRange.Split('.');

            beginIP = new byte[4];
            endIP = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string[] rangeParts = ipParts[i].Split('-');

                if (rangeParts.Length < 1 || rangeParts.Length > 2)
                    return false;

                beginIP[i] = byte.Parse(rangeParts[0]);
                endIP[i] = (rangeParts.Length == 1) ? beginIP[i] : byte.Parse(rangeParts[1]);
            }

            return true;
        }

        private byte [] beginIP;
        private byte [] endIP;
    }
    class Processing {
        public static void Output(string Log, Types.LogLevel Level = Types.LogLevel.INFO) {
            string prefix;
            switch (Level) {
                case Types.LogLevel.INFO:
                    prefix = "[INFO]";
                    break;
                case Types.LogLevel.WARN:
                    prefix = "[WARN]";
                    break;
                case Types.LogLevel.ERROR:
                    prefix = "[ERROR]";
                    break;
                default:
                    prefix = "[UKNN]";
                    break;
            }
            Console.WriteLine(prefix + " " + Log);
        }
        /// <summary>
        /// Verify if an IP range is valid and decodable
        /// Example: '0-255.0-255.0-255.0-255' is the whole IPv4 space
        /// </summary>
        /// <param name="Range"></param>
        public static bool VerifyIPRange(string Range) {
            try {
                var IPs = new IPRange(Range);
                Output("Parsed " + IPs.GetAllIP().Count() + " IP(s).");
                return true;
            } catch (Exception ex) {
                Output("Unable to decode the IP range: " + ex.ToString(), LogLevel.ERROR);
                return false;
            }
        }
        
        public static bool VerifyPort(int Port) {
            if (Port < 1 || Port > 65535) { return false; } else { return true; }
        }

        public static bool VerifyPortRange(string Range) {
            try {
                if (Range.Contains("-")) {
                    int DashLocation = Range.IndexOf("-");
                    int BeginPort = int.Parse(Range.Substring(0, DashLocation));
                    int EndPort = int.Parse(Range.Substring(DashLocation + 1, Range.Length - DashLocation - 1));
                    if (VerifyPort(BeginPort) == false) { return false; }
                    if (VerifyPort(EndPort) == false) { return false; }
                    if (BeginPort > EndPort) { return false; }
                    return true;
                } else {
                    if (VerifyPort(int.Parse(Range)) == false) { return false; }
                    return true;
                }
            } catch (Exception ex) {
                Output("Invalid Port range: " + Range + ": " + ex.ToString(), LogLevel.ERROR);
                return false;
            }
        }
        
        /// <summary>
        /// Be sure to verify the range before using this method!
        /// </summary>
        /// <param name="Range"></param>
        /// <returns></returns>
        public static List<int> GetPorts(string Range) {
            List<int> ListToReturn = new List<int>();
            if (Range.Contains("-")) {
                int DashLocation = Range.IndexOf("-");
                int BeginPort = int.Parse(Range.Substring(0, DashLocation));
                int EndPort = int.Parse(Range.Substring(DashLocation + 1, Range.Length - DashLocation - 1));
                for (int i = BeginPort; i <= EndPort; i++) {
                    ListToReturn.Add(i);
                }
                Output(EndPort - BeginPort + 1 + " port(s) added.");
                return ListToReturn;
            } else {
                ListToReturn.Add(int.Parse(Range));
                Output("1 port(s) added.");
                return ListToReturn;
            }
        }

        public static string GetInput() {
            Console.Write("==> ");
            return Console.ReadLine();
        }

        public static bool GetBoolByYN(string Input, bool DefaultBool) {
            switch (Input.ToLower()) {
                case "y":
                    return true;
                case "n":
                    return false;
                default:
                    return DefaultBool;
            }
        }

        public static async Task<bool> DetectICMP(IPAddress IP) {
            try {
                Ping Pinger = new Ping();
                await Pinger.SendPingAsync(IP);
                return true;
            } catch {
                return false;
            }
        }

        public static void StartTCP(IPAddress IP, int Port) {
            Thread PortThr = new Thread(() => DetectTCP(IP, Port));
            PortThr.SetApartmentState(ApartmentState.MTA);
            GC.Collect();
            try {
                PortThr.Start();
            } catch (OutOfMemoryException) {
                Output("Insufficient memory! Will wait for 3 seconds and continue.", LogLevel.WARN);
                Thread.Sleep(3000);
                StartTCP(IP, Port);
            }
        }

        public static bool DetectTCP(IPAddress IP, int Port) {
            try {
                var Sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                var EndPoint = new IPEndPoint(IP, Port);
                Sock.Blocking = true;
                IAsyncResult Result = Sock.BeginConnect(IP, Port, null, null);
                for (int i = 0; i <= 5000; i += 100) {
                    bool Success = Result.AsyncWaitHandle.WaitOne(100, true);
                    if (Sock.Connected) {
                        Sock.EndConnect(Result);
                        Sock.Dispose();
                        Output("[OPEN] " + IP.ToString() + ":" + Port + " - TCPConnect");
                        return true;
                    }
                }
                Sock.Dispose();
                throw (new TimeoutException("Request timed out (5000 milliseconds)."));
            } catch {
                // Output("[CLOSED] " + IP.ToString() + ":" + Port + " - TCP");
                return false;
            }
        }

        // ========== !!!!!!!!!! ==========
        // The following stuff belong to
        // Setup, do not add things that
        // were not related to Setup below.
        // !!!!!!!!!! ========== !!!!!!!!!!

        /// <summary>
        /// Launch setup.
        /// </summary>
        public static void InitSetup() {
            // prompt user to setup the PScan every when it starts.
            AddIPRanges();
            AddPortRanges();
            Output("==> Do you need to check ICMP packages' transmission? [y/N]");
            Consts.TestICMP = GetBoolByYN(GetInput(), false);
        }

        private static void AddIPRanges() {
            // prompt user to set ip range
            Output("==> Please input a valid IP range.");
            Output("==> Example: 1.1.1.1 or 1.1-10.1.1.");
            string IPRangeInput = GetInput();
            if (VerifyIPRange(IPRangeInput) == false) {
                Output("IP range verification failed. Check your input and try again.", LogLevel.ERROR);
                Environment.Exit(1);
            }
            Consts.IPRanges.Add(new IPRange(IPRangeInput));
            Output("==> Would you like to add more IP ranges? [y/N]");
            string Confirm = GetInput();
            switch (Confirm.ToLower()) {
                case "y":
                    AddIPRanges();
                    break;
                default:
                    return;
            }
        }

        private static void AddPortRanges() {
            Output("==> Please input a valid Port range.");
            Output("==> Example: 1-10 or 80-443.");
            string Ports = GetInput();
            if (VerifyPortRange(Ports) == false) {
                Output("Port range verification failed. Check your input and try again.", LogLevel.ERROR);
                Environment.Exit(1);
            }
            foreach (int i in GetPorts(Ports)) { Consts.Ports.Add(i); }
            Output("==> Would you like to add more port ranges? [y/N]");
            string Confirm = GetInput();
            switch (Confirm.ToLower()) {
                case "y":
                    AddPortRanges();
                    break;
                default:
                    return;
            }
        }
    }
}
