import argparse
import socket
import sys
import csv
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Scapy imports for advanced scanning
try:
    from scapy.all import IP, ICMP, UDP, TCP, sr1, sr
except ImportError:
    print("Error: Scapy is required for SYN/UDP/ICMP scans. Install with 'pip install scapy'.")
    sys.exit(1)

COMMON_SERVICES = {
    21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 25: 'SMTP', 110: 'POP3'
}


def icmp_ping(host, timeout=1):
    pkt = IP(dst=host)/ICMP()
    resp = sr1(pkt, timeout=timeout, verbose=0)
    return resp is not None


def tcp_connect_scan(host, port, timeout=1):
    result = {"port": port, "protocol": "TCP-CONNECT", "status": "closed",
              "banner": "", "ttl": None, "window": None, "service": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            result["status"] = "open"
            # banner & os fingerprint
            try:
                banner = s.recv(1024).decode(errors='ignore').strip()
                result["banner"] = banner
            except:
                pass
            # OS fingerprint: TTL/window from system? Skip for connect
            # Service detection
            svc = COMMON_SERVICES.get(port)
            if svc == 'HTTP':
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                resp = s.recv(1024).decode(errors='ignore')
                result['banner'] = resp.split('\r\n')[0]
                result['service'] = 'HTTP'
            elif svc:
                result['service'] = svc
    except:
        pass
    return result


def tcp_syn_scan(host, port, timeout=1):
    result = {"port": port, "protocol": "TCP-SYN", "status": "filtered" ,
              "ttl": None, "window": None}
    pkt = IP(dst=host)/TCP(dport=port, flags='S')
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = 'filtered'
    elif resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            result["status"] = 'open'
            result['ttl'] = resp.ttl
            result['window'] = resp[TCP].window
            # send RST to close
            rst = IP(dst=host)/TCP(dport=port, flags='R')
            sr(rst, timeout=timeout, verbose=0)
        elif resp[TCP].flags == 0x14:  # RST-ACK
            result["status"] = 'closed'
    return result


def udp_scan(host, port, timeout=1):
    result = {"port": port, "protocol": "UDP", "status": "open|filtered"}
    pkt = IP(dst=host)/UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        result["status"] = 'open|filtered'
    elif resp.haslayer(ICMP):
        # ICMP unreachable
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            result["status"] = 'closed'
    return result


def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def scan_host(host, ports, workers, timeout, methods):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []
        if 'ping' in methods:
            alive = icmp_ping(host, timeout)
            print(f"Host {host} is {'alive' if alive else 'down'} via ICMP")
            if not alive:
                return []
        for port in ports:
            for m in methods:
                if m == 'connect':
                    futures.append(executor.submit(tcp_connect_scan, host, port, timeout))
                elif m == 'syn':
                    futures.append(executor.submit(tcp_syn_scan, host, port, timeout))
                elif m == 'udp':
                    futures.append(executor.submit(udp_scan, host, port, timeout))
        for f in as_completed(futures):
            results.append(f.result())
    return results


def format_text(host, data):
    print(f"\nScan report for {host}")
    print(f"Time: {datetime.now()}\n")
    for r in sorted(data, key=lambda x: (x['protocol'], x['port'])):
        line = f" {r['port']:>5}/{r['protocol']} {r['status']}"
        if 'banner' in r and r.get('banner'):
            line += f" | Banner: {r['banner']}"
        if r.get('ttl'):
            line += f" | TTL: {r['ttl']}"
        if r.get('window'):
            line += f" | Win: {r['window']}"
        print(line)


def format_csv(host, data, filename):
    keys = set().union(*(d.keys() for d in data))
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['port','protocol','status','banner','ttl','window','service'])
        writer.writeheader()
        for d in data:
            writer.writerow(d)
    print(f"CSV report saved to {filename}")


def format_html(host, data, filename):
    rows = ''
    for r in sorted(data, key=lambda x: (x['protocol'], x['port'])):
        rows += '<tr>' + ''.join(f'<td>{r.get(k,"")}</td>' for k in ['port','protocol','status','banner','ttl','window','service']) + '</tr>'
    html = f"""
    <html><head><title>Scan {host}</title></head><body>
    <h1>Scan report for {host}</h1>
    <p>Time: {datetime.now()}</p>
    <table border="1"><tr><th>Port</th><th>Proto</th><th>Status</th><th>Banner</th><th>TTL</th><th>Win</th><th>Service</th></tr>
    {rows}
    </table></body></html>
    """
    with open(filename, 'w') as f:
        f.write(html)
    print(f"HTML report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description="Advanced mini-nmap CLI scanner")
    parser.add_argument('host', help="Target hostname/IP")
    parser.add_argument('-p','--ports', default='1-1024', help="Ports e.g. '22,80' or '1-1000'")
    parser.add_argument('-m','--methods', nargs='+', choices=['connect','syn','udp','ping'], default=['connect'],
                        help="Scan methods: connect, syn, udp, ping")
    parser.add_argument('-t','--timeout', type=float, default=1.0)
    parser.add_argument('-w','--workers', type=int, default=100)
    parser.add_argument('--csv', metavar='FILE', help="Write CSV report")
    parser.add_argument('--html', metavar='FILE', help="Write HTML report")
    parser.add_argument('-j','--json', action='store_true', help="Print JSON to stdout")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Cannot resolve {args.host}")
        sys.exit(1)

    ports = parse_ports(args.ports)
    data = scan_host(ip, ports, args.workers, args.timeout, args.methods)

    if args.json:
        print(json.dumps({args.host: data}, indent=2))
    else:
        format_text(args.host, data)

    if args.csv:
        format_csv(args.host, data, args.csv)
    if args.html:
        format_html(args.host, data, args.html)

if __name__ == '__main__':
    main()
