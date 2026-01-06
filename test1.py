from scapy.all import rdpcap, IP, TCP
from collections import defaultdict
import statistics
import idba

PCAP_FILE = "/home/suraj/traffic.pcap"
ALERT_THRESHOLD = 7
WINDOW_SIZE = 300  # 5 minutes

flows = defaultdict(list)

packets = rdpcap(PCAP_FILE)

for pkt in packets:
    if IP in pkt and TCP in pkt:
        flags = pkt[TCP].flags
        if flags & 0x02:  # ignore SYN
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        timestamp = pkt.time
        size = len(pkt)

        flows[(src, dst, dport)].append((timestamp, size))

        # OPTIMIZE 

            # flows[(src, dst, dport)].append(
            #     (timestamp, size, src, dst, dport)
            # )

def window_packets(packets):
    windows = defaultdict(list)
    start = packets[0][0]

    # DEBUGING
    print(len(packets)) 
    for t, s in packets:
        window_id = int((t - start) // WINDOW_SIZE)
        windows[window_id].append((t, s))

    return windows.values()

def analyze_window(packets):
    if len(packets) < 5:
        return None

    times = [t for t, _ in packets]
    sizes = [s for _, s in packets]
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

    return {
        "mean_interval": statistics.mean(intervals),
        "size_variance": statistics.pvariance(sizes),
    }

def stability_score(windows):
    means = []
    for w in windows:
        features = analyze_window(w)
        if features:
            means.append(features["mean_interval"])

    if len(means) < 3:
        return 0

    # Bots jitter but stay centered
    variance = statistics.pvariance(means)
    return 3 if variance < 10 else 0

def base_score(packets):
    times = [t for t, _ in packets]
    sizes = [s for _, s in packets]

    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

    score = 0

    if statistics.pvariance(intervals) < 1:
        score += 3

    if statistics.pvariance(sizes) < 50:
        score += 2

    if len(packets) > 100:
        score += 2

    return score

for flow, packets in flows.items():
    if len(packets) < 30:
        continue

    windows = list(window_packets(packets))
    score = base_score(packets)
    score += stability_score(windows)

    if score >= ALERT_THRESHOLD:
        src, dst, port = flow
        print("\n[ALERT] ML-evasion-resistant detection")
        print(f"  {src} → {dst}:{port}")
        print(f"  Score: {score}")
        print(f"  Windows analyzed: {len(windows)}")
        print(f"  IDBA score: {idba.idba_score(packets,windows,flows)}")

