using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace HP.PortChecker {
    class PortChecker {
        private CountdownEvent allScans;
        private static Encoding iso8859_1 = Encoding.GetEncoding(28591);

        internal class BridgeIF {
            public string source = string.Empty;
            public string status = string.Empty;
            internal IPEndPoint ep = null;
            public string description = string.Empty;
        }

        private List<BridgeIF> bridges = new List<BridgeIF>();
        private bool verbose = false;

        static void Main(string[] args) {
            try {
                var tc = new PortChecker();
                tc.Run(args);
            }
            catch (Exception e) {
                Console.WriteLine($"{e.GetType()} thrown: {e.Message} \r\n {e.StackTrace}");
                Console.ReadLine();
            }
        }

        private void Run(string[] args) {
            allScans = new CountdownEvent(1);
            foreach (string arg in args) {
                if (string.Equals(arg, "-v")) {
                    verbose = true;
                    continue;
                }
                if (File.Exists(arg)) {
                    var lines = File.ReadAllLines(arg);
                    foreach (var line in lines) {
                        if (string.IsNullOrWhiteSpace(line))
                            continue;
                        var line2 = line.Trim();
                        if (line2.StartsWith("#"))
                            continue;
                        if (line2.ToLower().StartsWith("exit"))
                            break;
                        var fields = line2.Split(new char[] { ' ' }, 4, StringSplitOptions.RemoveEmptyEntries);
                        if (fields.Length < 3) {
                            Console.WriteLine($"line {line2} is not good enough ");
                            continue;
                        }
                        try {
                            var port = Int16.Parse(fields[2]);
                            string desc = string.Empty;
                            if (fields.Length >= 4) {
                                desc = fields[3];
                            }
                            try {
                                var he = Dns.GetHostEntry(fields[1]);
                                if (he.AddressList.Length < 1) {
                                    Console.WriteLine($"{arg} has no addresslist");
                                    continue;
                                }
                                foreach (var ipAddress in he.AddressList) {
                                    if (ipAddress.AddressFamily != AddressFamily.InterNetwork)
                                        continue;
                                    var br = new BridgeIF();
                                    br.source = fields[0];
                                    br.ep = new IPEndPoint(ipAddress, port);
                                    br.description = desc;
                                    bridges.Add(br);
                                }
                            }
                            catch (SocketException se) {
                                if (se.SocketErrorCode == SocketError.HostNotFound) {
                                    Console.WriteLine($"host {fields[1]} is not known to DNS!");
                                    // alternative
                                    try {
                                        var ipAddress = IPAddress.Parse(fields[1]);
                                        var br = new BridgeIF();
                                        br.source = fields[0];
                                        br.ep = new IPEndPoint(ipAddress, port);
                                        br.description = desc;
                                        bridges.Add(br);
                                    }
                                    catch (FormatException fe) {
                                        Console.Error.WriteLine($"second field must contain hostname or ip-address {fe.Message}");
                                        continue;
                                    }
                                }
                            }
                        }
                        catch (Exception ex) {
                            Console.WriteLine($"line {line2} cause {ex.GetType()}: {ex.Message} ");
                        }
                    }
                }
                else {
                    Console.WriteLine($"file {arg} does not exist");
                }
            }
            for (int idx = 0; idx < bridges.Count; ++idx) {
                allScans.AddCount();
                new Thread(TestEP).Start(idx);
            }
            allScans.Signal();
            allScans.Wait();
            int ol = 0;
            int h;
            if (Console.IsOutputRedirected) {
                h = bridges.Count * 2;
            }
            else {
                h = Console.WindowHeight - 2;
            }
            Console.WriteLine("----- -----");
            foreach (BridgeIF bridge in bridges) {
                Console.WriteLine($"{bridge.source} {bridge.ep} {bridge.description} -> {bridge.status}");
                if (++ol % h == 0) {
                    Console.Write("==>");
                    Console.ReadLine();
                }
            }
            Console.WriteLine();
            Console.WriteLine("all done, press enter");
            Console.ReadLine();
        }
        private void TestEP(object data) {
            BridgeIF bridge = null;
            NetworkStream ns = null;
            try {
                var idx = data as int?;
                if (idx == null)
                    return;
                bridge = bridges[idx.Value];
                Console.WriteLine($"testing {bridge.ep} ({bridge.source})");
                var tc = new TcpClient();
                tc.Connect(bridge.ep);
                var sendingApp = $"{bridge.source}";
                ns = tc.GetStream();
                bridge.status += "connected";
                ns.ReadTimeout = 1000;
                var timedOut = true;
                var msg = string.Empty;
                var ts = $"\vMSH|^~\\&|{bridge.source}|Test|Epic|Testing|20230101000000||MDM^T11|0|F|2.5||||||8859/1|\r" +
                    "NTE|1||Test message|\r" +
                    "G|Garbage, should get rejected|\r" +
                    "\x1c\r";
                var bb = iso8859_1.GetBytes(ts);
                ns.Write(bb, 0, bb.Length);
                ns.Flush();
                for (int tryNextMsg = 0; timedOut && (tryNextMsg < 10); ++tryNextMsg) {
                    timedOut = false;
                    bb = new byte[1024];
                    try {
                        while (true) {
                            var r = ns.Read(bb, 0, bb.Length);
                            if (r <= 0) {
                                Console.WriteLine($"zero bytes from {bridge.ep} ({bridge.source})");
                                break;
                            }
                            var str = iso8859_1.GetString(bb, 0, r);
                            msg += str;
                            if (msg.Contains("\x1c\r"))
                                break;
                        }
                    }
                    catch (IOException ioex) {
                        var nex = ioex.InnerException as SocketException;
                        if (nex?.SocketErrorCode == SocketError.TimedOut) {
                            timedOut = true;
                            ts = "\x1c\r\x1c\r\x1c\r\x1c\r\x1c\r\x1c\r\x1c\r\x1c\r\x1c\r\x1c\r";
                            bb = iso8859_1.GetBytes(ts);
                            ns.Write(bb, 0, bb.Length);
                            ns.Flush();
                            // Console.WriteLine($"{bridge.ep}({bridge.source}) timed out {tryNextMsg}");
                            Console.Write(".");
                        }
                    }
                }
                if (verbose) {
                    var str = msg.Replace("\r", "<CR>").Replace("\v", "<VT>").Replace("\x1c", "<FS>");
                    Console.WriteLine($"received {str}");
                }
                var lines = msg.Split('\r');
                if (lines.Length >= 2) {
                    var mshParts = lines[0].Split('|');
                    if (mshParts[2] != sendingApp) {
                        bridge.status += $" mismatch sent: {sendingApp}, received: {mshParts[2]}";
                    }
                    var msaParts = lines[1].Split('|');
                    if (msaParts.Length >= 3) {
                        int id = Int32.Parse(msaParts[2]);
                        if (id != 0) {
                            bridge.status += " jumped a message";
                        }
                    }
                    if ((msaParts.Length >= 4) && (msaParts[1] == "AR") && (msaParts[3] == "Incorrect Processing ID")) {
                        bridge.status += " ok";
                    }
                    else {
                        bridge.status += " not-ok: " + lines[0].Trim() + "<CR>" + lines[1].Trim();
                    }

                }
                else {
                    // Console.WriteLine($"{bridge.ep}({bridge.source}) missing length");
                    msg = msg.Replace("\v", "<VT>").Replace("\x1c", "<FS>").Replace("\r", "<CR>");
                    bridge.status += " " + msg;
                    if (timedOut) {
                        bridge.status += " timed out";
                    }
                }
            }
            catch (SocketException se) {
                if (se.SocketErrorCode == SocketError.ConnectionRefused) {
                    bridge.status = "closed";
                }
                else if (se.SocketErrorCode == SocketError.TimedOut) {
                    bridge.status = "timed out";
                }
                else {
                    bridge.status = $"{se.GetType()}: {se.Message} {se.StackTrace}";
                }
            }
            catch (Exception ex) {
                if (bridge == null) {
                    Console.WriteLine($"no bridge info {ex.GetType()}: {ex.Message} {ex.StackTrace}");
                    return;
                }
                bridge.status += $"{ex.GetType()}: {ex.Message} {ex.StackTrace}";
            }
            finally {
                allScans.Signal();
                ns?.Close();
            }
        }
    }
}
