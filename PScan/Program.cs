using System;
using static PScan.Processing;

namespace PScan {
    class Program {
        public static void Main(string[] args) {
            Console.WriteLine("PScan version " + Consts.AppVer);
            Output("Starting setup...");
            Processing.InitSetup();
        }
    }
}
