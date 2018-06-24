using System;
using System.Net;
using System.Web;
using System.Threading;
using System.Threading.Tasks;
using static PScan.Processing;
using static PScan.Types;

namespace PScan {
    class Program {
        public static async Task MainAsync(string[] args) {
            Console.WriteLine("PScan version " + Consts.AppVer);
            Output("Starting setup...");
            Processing.InitSetup();
            Output("Starting scanning...");
            // actual scan process
            Consts.Timer.Start();
            try {
                foreach (IPRange Range in Consts.IPRanges) {
                    Output("Calculating IPs...");
                    foreach (IPAddress IP in Range.GetAllIP()) {
                        Output("==> Now scanning IP: " + IP.ToString());
                        // detect ICMP in advance
                        if (await DetectICMP(IP) == true) { Output("[OPEN] " + IP.ToString() + " - ICMP"); } else { Output("[CLOSED] " + IP.ToString() + " - ICMP"); }
                        foreach (int Port in Consts.Ports) {
                            // do tcping
                            StartTCP(IP, Port);
                        }
                    }
                }
            } catch (Exception ex) {
                Output("Unexpected error: " + ex.ToString(), LogLevel.ERROR);
            }
        }

        public static void Main(string[] args) {
            Task MainTask = MainAsync(args);
            MainTask.Wait();

            Consts.Timer.Stop();
            Output("Scan complete.");
            Output("Total elapsed time: " + Consts.Timer.Elapsed.ToString());
        }
    }
}
