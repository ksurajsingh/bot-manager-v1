from scapy.all import rdpcap, IP, TCP
from collections import defaultdict,Counter
import statistics
import math

CIRCADIAN_GAP = 3 * 60 * 60    # 3 hours
MIN_OBSERVATION = 6 * 60 * 60 # 6 hours total activity span

def circadian_score(packets):
    """
    packets: list of (timestamp, size)
    """
    if len(packets) < 20:
        return 0

    times = sorted(t for t, _ in packets)

    total_span = times[-1] - times[0]
    if total_span < MIN_OBSERVATION:
        return 0

    gaps = [times[i+1] - times[i] for i in range(len(times)-1)]


    if max(gaps) >= 3*60*60:
        score=4
    elif max(gaps) >= 2*60*60:
        score=2


                    # TODO: USEME
                    # long_gaps = [g for g in gaps if g >= CIRCADIAN_GAP]
                    #
                    # # Humans usually have at least one long idle gap
                    # if len(long_gaps) == 0:
                    #     return 4   # strong automation signal

                    

                    # FIX: if the length of 0 then obviously active_time = total_span , hence active_ratio is always 1
                    # active_time = total_span - sum(long_gaps)
                    # active_ratio = active_time / total_span
                    # if len(long_gaps) == 0 and active_ratio > ACTIVE_RATIO_THRESHOLD:
                    #     return 4




def destination_entropy_score(flows):
    dsts = [dst for (_, dst, _) in flows.keys()]

    if len(dsts) < 5:
        return 0

    counts = Counter(dsts)
    total = len(dsts)

    entropy = -sum(
        (c/total) * math.log2(c/total)
        for c in counts.values()
    )

    return 3 if entropy < 1.5 else 0

def rr_ratio_score(windows):


    # change the actual flows data structure , right now I am doing just not to break
    # the data model in other functions 


    temp_flows = defaultdict(list)

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

            flows[(src, dst, dport)].append((timestamp, size,src))



        windows = list(window_packets(packets))  # [(t,size,src)]

        for w in windows:
            up = 0
            down = 0
            for t, size, packet_src in w:
                if packet_src == my_ip:
                    up += size
                else:
                    down += size

        if down > 0:
            ratios.append(up / down)

    if len(ratios) < 3:
        return 0

    variance = statistics.pvariance(ratios)
    return 3 if variance < 0.1 else 0


def session_length_score(packets):
    times = [t for t, *_ in packets]
    span = max(times) - min(times)

    return 2 if span > 12 * 60 * 60 else 0




def idba_score(packets, windows, flows):
    score = 0
    score += destination_entropy_score(flows)
    score += rr_ratio_score(windows)
    score += circadian_score(packets)
    score += session_length_score(packets)
    return score
    """
    0-4   Likely human behavior
    5-7   Suspicious / semi-consistent 
    8-10  Consistent / Review Required
    11-12 Highly Consistent / bot-like
    """

