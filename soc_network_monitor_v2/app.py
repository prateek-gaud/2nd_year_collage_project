#!/usr/bin/env python3
import os, time, json, sqlite3, threading, queue, socket, csv, io, hashlib
from datetime import datetime, timezone
from collections import defaultdict, deque

import psutil
from flask import Flask, jsonify, render_template, request, Response, send_file
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "soc_monitor.db")
PACKET_QUEUE = queue.Queue(maxsize=10000)
INTERFACE = os.getenv("SOC_INTERFACE") or None
CAPTURE_FILTER = os.getenv("SOC_BPF", "ip or ip6 or arp")

app = Flask(__name__)
state_lock = threading.Lock()
state = {
    "packets": 0, "bytes": 0, "started": time.time(), "last_packet": None,
    "protocols": defaultdict(int), "top_talkers": defaultdict(lambda: {"packets":0,"bytes":0}),
    "flows": {}, "alerts": deque(maxlen=1000), "dropped": 0
}
scan_tracker = defaultdict(lambda: deque(maxlen=2000))
dns_tracker = defaultdict(lambda: deque(maxlen=1000))

def utcnow(): return datetime.now(timezone.utc).isoformat()

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, severity TEXT, rule TEXT,
      src_ip TEXT, dst_ip TEXT, message TEXT, metadata TEXT
    );
    CREATE TABLE IF NOT EXISTS packets(
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, src_ip TEXT, dst_ip TEXT,
      protocol TEXT, src_port INTEGER, dst_port INTEGER, length INTEGER, flags TEXT,
      interface TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
    CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
    """)
    c.close()

def add_alert(severity, rule, src, dst, message, metadata=None):
    a={"ts":utcnow(),"severity":severity,"rule":rule,"src_ip":src,"dst_ip":dst,
       "message":message,"metadata":metadata or {}}
    with state_lock: state["alerts"].appendleft(a)
    c=db(); c.execute("INSERT INTO alerts(ts,severity,rule,src_ip,dst_ip,message,metadata) VALUES(?,?,?,?,?,?,?)",
                      (a["ts"],severity,rule,src,dst,message,json.dumps(metadata or {})))
    c.commit(); c.close()

def proto(pkt):
    if ARP in pkt: return "ARP"
    if ICMP in pkt: return "ICMP"
    if TCP in pkt: return "TCP"
    if UDP in pkt and DNS in pkt: return "DNS"
    if UDP in pkt: return "UDP"
    if IPv6 in pkt: return "IPv6"
    return "OTHER"

def summary(pkt):
    p=proto(pkt); src=dst=None; sp=dp=None; flags=""
    if IP in pkt: src,dst=pkt[IP].src,pkt[IP].dst
    elif IPv6 in pkt: src,dst=pkt[IPv6].src,pkt[IPv6].dst
    elif ARP in pkt: src,dst=pkt[ARP].psrc,pkt[ARP].pdst
    if TCP in pkt: sp,dp=int(pkt[TCP].sport),int(pkt[TCP].dport); flags=str(pkt[TCP].flags)
    elif UDP in pkt: sp,dp=int(pkt[UDP].sport),int(pkt[UDP].dport)
    return src,dst,p,sp,dp,flags,len(pkt)

def detect(pkt,src,dst,p,sp,dp,flags,length):
    now=time.time()
    if TCP in pkt and src and dst and "S" in flags and "A" not in flags:
        k=(src,dst); scan_tracker[k].append((now,dp))
        recent=[x for x in scan_tracker[k] if now-x[0]<15]
        ports={x[1] for x in recent}; scan_tracker[k]=deque(recent,maxlen=2000)
        if len(ports)>=15:
            add_alert("high","TCP_PORT_SCAN",src,dst,f"Possible TCP port scan: {len(ports)} ports / 15s",
                      {"unique_ports":len(ports)})
            scan_tracker[k].clear()
    clear={21:"FTP",23:"Telnet",80:"HTTP",110:"POP3",143:"IMAP",25:"SMTP"}
    if p=="TCP" and dp in clear:
        add_alert("medium","CLEARTEXT_PROTOCOL",src,dst,f"Observed {clear[dp]} on TCP/{dp}",{"port":dp})
    if DNS in pkt and DNSQR in pkt:
        try:
            q=pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if len(q)>80: add_alert("medium","LONG_DNS_QUERY",src,dst,f"Long DNS query ({len(q)} chars)",
                                      {"qname":q[:160],"length":len(q)})
        except Exception: pass
    if TCP in pkt and flags=="S":
        k=(src,dst); scan_tracker[k].append((now,dp))
    if length>1400:
        add_alert("low","LARGE_PACKET",src,dst,f"Large packet observed ({length} bytes)",{"length":length})

def worker():
    c=db(); batch=[]; last=time.time()
    while True:
        pkt=PACKET_QUEUE.get()
        try:
            src,dst,p,sp,dp,flags,length=summary(pkt)
            with state_lock:
                state["packets"]+=1; state["bytes"]+=length; state["last_packet"]=utcnow()
                state["protocols"][p]+=1
                if src: state["top_talkers"][src]["packets"]+=1; state["top_talkers"][src]["bytes"]+=length
                if src and dst:
                    k=f"{src}|{dst}|{p}|{sp or 0}|{dp or 0}"
                    f=state["flows"].setdefault(k,{"src":src,"dst":dst,"protocol":p,"sport":sp,"dport":dp,
                                                    "packets":0,"bytes":0,"first_seen":utcnow(),"last_seen":utcnow()})
                    f["packets"]+=1; f["bytes"]+=length; f["last_seen"]=utcnow()
            detect(pkt,src,dst,p,sp,dp,flags,length)
            batch.append((utcnow(),src,dst,p,sp,dp,length,flags,INTERFACE or "default"))
            if len(batch)>=100 or time.time()-last>2:
                c.executemany("INSERT INTO packets(ts,src_ip,dst_ip,protocol,src_port,dst_port,length,flags,interface) VALUES(?,?,?,?,?,?,?,?,?)",batch)
                c.commit(); batch.clear(); last=time.time()
        except Exception as e: print("worker:",e)
        finally: PACKET_QUEUE.task_done()

def capture(pkt):
    try: PACKET_QUEUE.put_nowait(pkt)
    except queue.Full:
        with state_lock: state["dropped"]+=1

def capture_loop():
    print(f"[+] capture interface={INTERFACE or 'default'} filter={CAPTURE_FILTER}")
    sniff(iface=INTERFACE,filter=CAPTURE_FILTER,prn=capture,store=False)

def interfaces():
    out=[]
    stats=psutil.net_if_stats(); addrs=psutil.net_if_addrs()
    for name in sorted(stats):
        s=stats[name]
        ips=[a.address for a in addrs.get(name,[]) if getattr(a,"family",None) in (socket.AF_INET,socket.AF_INET6)]
        out.append({"name":name,"up":s.isup,"speed":s.speed,"mtu":s.mtu,"ips":ips})
    return out

def system():
    n=psutil.net_io_counters(); m=psutil.virtual_memory()
    return {"hostname":socket.gethostname(),"cpu":psutil.cpu_percent(),"memory_percent":m.percent,
            "sent":n.bytes_sent,"recv":n.bytes_recv,"uptime":int(time.time()-state["started"])}

@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/interfaces")
def api_interfaces(): return jsonify(interfaces())

@app.route("/api/overview")
def overview():
    with state_lock:
        t=[{"ip":k,**v} for k,v in state["top_talkers"].items()]
        t.sort(key=lambda x:x["bytes"],reverse=True)
        f=list(state["flows"].values()); f.sort(key=lambda x:x["bytes"],reverse=True)
        return jsonify({"packets":state["packets"],"bytes":state["bytes"],"dropped":state["dropped"],
                        "protocols":dict(state["protocols"]),"talkers":t[:15],"flows":f[:50],
                        "alerts":list(state["alerts"])[:50],"system":system(),
                        "interface":INTERFACE or "default","last_packet":state["last_packet"]})

@app.route("/api/alerts")
def api_alerts():
    limit=min(int(request.args.get("limit",200)),1000); c=db()
    rows=c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?",(limit,)).fetchall(); c.close()
    out=[]
    for r in rows:
        d=dict(r); d["metadata"]=json.loads(d["metadata"] or "{}"); out.append(d)
    return jsonify(out)

@app.route("/api/packets")
def api_packets():
    limit=min(int(request.args.get("limit",200)),1000); c=db()
    rows=c.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?",(limit,)).fetchall(); c.close()
    return jsonify([dict(x) for x in rows])

def export_rows(kind,fmt):
    c=db()
    if kind=="alerts": rows=c.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    else: rows=c.execute("SELECT * FROM packets ORDER BY id DESC").fetchall()
    c.close(); rows=[dict(r) for r in rows]
    if fmt=="json":
        return Response(json.dumps(rows,indent=2),mimetype="application/json",
                        headers={"Content-Disposition":f"attachment; filename={kind}.json"})
    if fmt=="csv":
        s=io.StringIO(); w=csv.DictWriter(s,fieldnames=list(rows[0].keys()) if rows else ["id"])
        w.writeheader(); w.writerows(rows)
        return Response(s.getvalue(),mimetype="text/csv",
                        headers={"Content-Disposition":f"attachment; filename={kind}.csv"})
    return jsonify({"error":"format must be csv or json"}),400

@app.route("/export/<kind>/<fmt>")
def export(kind,fmt):
    if kind not in ("alerts","packets"): return jsonify({"error":"invalid export"}),400
    return export_rows(kind,fmt)

@app.route("/api/clear-alerts",methods=["POST"])
def clear_alerts():
    c=db(); c.execute("DELETE FROM alerts"); c.commit(); c.close()
    with state_lock: state["alerts"].clear()
    return jsonify({"ok":True})

@app.route("/api/health")
def health(): return jsonify({"status":"ok","interface":INTERFACE or "default","filter":CAPTURE_FILTER})

if __name__=="__main__":
    init_db()
    threading.Thread(target=worker,daemon=True).start()
    threading.Thread(target=capture_loop,daemon=True).start()
    app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")),debug=False)
