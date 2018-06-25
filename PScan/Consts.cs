using System;
using System.Diagnostics;
using System.Reflection;
using System.Collections.Generic;
using System.IO;

namespace PScan {
    class Consts {
        public readonly static Version AppVer = new Version("1.0.1.0");
        public readonly static string AppExecutable = Assembly.GetExecutingAssembly().Location;
        public readonly static string AppDirectory = (new FileInfo(AppExecutable)).DirectoryName;

        // these following variables will be able to be edited at runtime to store temporary configurations.
        public static List<IPRange> IPRanges {get; set;} = new List<IPRange>();
        public static List<int> Ports {get; set;} = new List<int>();

        // function switches
        public static bool TestICMP {get; set;} = false;

        // timer
        public static Stopwatch Timer {get;} = new Stopwatch();
    }
}
