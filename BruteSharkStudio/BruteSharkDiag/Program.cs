using System;using System.Collections.Generic;using System.IO;using System.Linq;using System.Threading;
using PcapProcessor;using PcapAnalyzer;
class P{static int Main(){string d=@"C:\WireSharkTools\BruteSharkPro\Pcap_Examples\Combined_Test";
var f=new HashSet<string>(Directory.GetFiles(d,"*.pcap*").Concat(Directory.GetFiles(d,"*.cap")));
var a=new Analyzer();var t=new HashSet<string>();a.ParsedItemDetected+=(s,e)=>{lock(t)t.Add(e.ParsedItem.GetType().Name);};
foreach(var n in a.AvailableModulesNames)a.AddModule(n);
var p=new Processor{BuildTcpSessions=true,BuildUdpSessions=true};
p.UdpPacketArived+=(s,e)=>a.Analyze(CommonUi.Casting.CastProcessorUdpPacketToAnalyzerUdpPacket(e.Packet));
p.TcpPacketArived+=(s,e)=>a.Analyze(CommonUi.Casting.CastProcessorTcpPacketToAnalyzerTcpPacket(e.Packet));
p.TcpSessionArrived+=(s,e)=>a.Analyze(CommonUi.Casting.CastProcessorTcpSessionToAnalyzerTcpSession(e.TcpSession));
p.UdpSessionArrived+=(s,e)=>a.Analyze(CommonUi.Casting.CastProcessorUdpStreamToAnalyzerUdpStream(e.UdpSession));
var done=new ManualResetEventSlim(false);p.ProcessingFinished+=(s,e)=>done.Set();
Console.WriteLine("Processing "+f.Count+" files...");
new Thread(()=>p.ProcessPcaps(f)).Start();done.Wait(TimeSpan.FromMinutes(3));Thread.Sleep(500);
Console.WriteLine("\nTypes detected:");foreach(var x in t.OrderBy(x=>x))Console.WriteLine("  "+x);
foreach(var e in new[]{"NetworkPassword","NetworkHash","NtlmHash","KerberosHash","CramMd5Hash","HttpDigestHash","NetworkConnection","NetworkFile","DnsNameMapping","VoipCall","Ja3Fingerprint","BeaconResult","PayloadAlert","DhcpLease","SshServerFingerprint","HttpTransaction","TlsCertificate","DnsExfilAlert"})
Console.WriteLine((t.Any(x=>x==e||(e=="NetworkHash"&&(x=="NtlmHash"||x=="KerberosHash"||x=="CramMd5Hash"||x=="HttpDigestHash")))?"✅":"❌")+" "+e);
return 0;}}
