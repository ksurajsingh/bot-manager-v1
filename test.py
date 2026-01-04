from scapy.all import rdpcap, IP, TCP
from collections import defaultdict
import statistics

PCAP_FILE = "/home/suraj/traffic.pcap"
ALERT_THRESHOLD = 5

flows = defaultdict(list)

# 1. Read packets and extract metadata
packets = rdpcap(PCAP_FILE)

for pkt in packets:
    if IP in pkt and TCP in pkt:
        # ignore handshake packets
        flags = pkt[TCP].flags
        if flags & 0x02:   # SYN
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        timestamp = pkt.time
        size = len(pkt)

        key = (src, dst, dport)
        flows[key].append((timestamp, size))

# 2. Analyze each flow
def analyze_flow(packets):
    if len(packets) < 10:
        return None

    times = [t for t, _ in packets]
    sizes = [s for _, s in packets]

    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

    return {
        "count": len(packets),
        "interval_variance": statistics.pvariance(intervals) if len(intervals) > 1 else 0,
        "size_variance": statistics.pvariance(sizes),
        "mean_interval": statistics.mean(intervals),
    }

# 3. Score behavior
def score(features):
    score = 0

    if features["interval_variance"] < 1:
        score += 3

    if features["size_variance"] < 50:
        score += 2

    if features["count"] > 100:
        score += 2

    if features["mean_interval"] < 60:
        score += 1

    return score

# 4. Detection
for flow, pkts in flows.items():
    features = analyze_flow(pkts)
    if not features:
        continue

    s = score(features)

    if s >= ALERT_THRESHOLD:
        src, dst, port = flow
        print(f"\n[ALERT] Suspicious encrypted channel")
        print(f"  {src} → {dst}:{port}")
        print(f"  Score: {s}")
        print(f"  Features: {features}")

