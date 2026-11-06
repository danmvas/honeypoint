#!/usr/bin/env python3
import os, struct, socket, threading, time, json, glob, sys, tempfile
LOGDIR = tempfile.mkdtemp(prefix="sc_rdp_"); os.environ["STAGED_LOG_DIR"]=LOGDIR
sys.path.insert(0,"hp")
from framework.tracker import SCTracker
from drivers.bluekeep import BlueKeepDriver
from drivers.ms12_020 import MS12020Driver

PORT=13389
def tpkt(p): return struct.pack(">BBH",3,0,len(p)+4)+p
def x224d(p): return tpkt(b"\x02\xf0\x80"+p)
def cr():
    cookie=b"Cookie: mstshash=probe\r\n"
    body=struct.pack(">BBHHB",6+len(cookie),0xE0,0,0,0)+cookie
    return tpkt(body)
def connect_initial():
    cs=struct.pack("<HH",0xC001,216)+b"\x04\x00\x08\x00"+b"\x00"*208
    return x224d(b"\x7f\x65\x82\x01\x3d"+b"\x00"*8+cs)
def erect(): return x224d(b"\x04\x01\x00\x01\x00\x01\x00\x01\x00")
def attach(): return x224d(b"\x28")
def join(initiator,channel): return x224d(struct.pack(">BHH",0x38,initiator,channel))
def senddata(): return x224d(struct.pack(">BHHBH",0x64,1001,31,0x70,8)+b"\x41"*8)

for cls in (BlueKeepDriver, MS12020Driver):
    d=cls(); m=d.get_metadata(); t=SCTracker.from_metadata(m)
    threading.Thread(target=d.start,args=(PORT,t),daemon=True).start()
    time.sleep(0.15)
time.sleep(1.2)

def run(seq,label):
    wire=[]; s=socket.create_connection(("127.0.0.1",PORT),timeout=5)
    for msg in seq:
        wire.append((time.time(),"c",msg)); s.sendall(msg); time.sleep(0.05)
        try:
            r=s.recv(8192)
            if r: wire.append((time.time(),"s",r))
        except socket.timeout: pass
    s.close(); time.sleep(0.6)
    return wire

def write_pcap(path,w,sport):
    out=bytearray(struct.pack("<IHHiIII",0xa1b2c3d4,2,4,0,0,65535,1)); seq={"c":1,"s":1}
    for ts,who,pl in w:
        src,dst=("10.0.0.2","10.0.0.1") if who=="c" else ("10.0.0.1","10.0.0.2")
        sp,dp=(sport,PORT) if who=="c" else (PORT,sport)
        tcp=struct.pack(">HHIIBBHHH",sp,dp,seq[who],0,5<<4,0x18,8192,0,0); seq[who]+=len(pl)
        body=tcp+pl
        ip=struct.pack(">BBHHHBBH",0x45,0,20+len(body),0,0,64,6,0)
        ip+=bytes(int(x) for x in src.split("."))+bytes(int(x) for x in dst.split("."))
        fr=b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"+ip+body
        out+=struct.pack("<IIII",int(ts),int((ts%1)*1e6),len(fr),len(fr))+fr
    open(path,"wb").write(bytes(out))

bk = run([cr(),connect_initial(),erect(),attach(),join(1001,31),senddata()],"bluekeep")
write_pcap("out/selftest_bluekeep.pcap",bk,50001)
ms = run([cr(),connect_initial(),erect(),attach(),attach(),join(1001,1002)],"ms12020")
write_pcap("out/selftest_ms12020.pcap",ms,50002)

for f in sorted(glob.glob(os.path.join(LOGDIR,"sc_*.json"))):
    j=json.load(open(f))
    print("SC_int %-10s %d/%d stages=%s" % (j["driver_name"], j["completed_stages"],
          j["total_stages"], sorted(e["stage_number"] for e in j["events"])))
