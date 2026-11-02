import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

T_START, T_END, T_DATA, T_ACK = 0, 1, 2, 3
CHUNK = 1472 - 16
RTO = 0.5


def encode(kind, seq, body=b""):
    hdr = PacketHeader(type=kind, seq_num=seq, length=len(body), checksum=0)
    hdr.checksum = compute_checksum(bytes(hdr) + body)
    return bytes(hdr) + body


def recv_ack(sock, deadline):
    """Block until a valid ACK arrives (return its seq) or the deadline passes (None)."""
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        sock.settimeout(left)
        try:
            raw, _ = sock.recvfrom(2048)
        except socket.timeout:
            return None
        if len(raw) < 16:
            continue
        hdr = PacketHeader(raw[:16])
        given = hdr.checksum
        hdr.checksum = 0
        if hdr.type == T_ACK and compute_checksum(bytes(hdr) + raw[16:16 + hdr.length]) == given:
            return hdr.seq_num


def run(ip, port, window):
    peer = (ip, port)
    payload = sys.stdin.buffer.read()
    frames = {}
    n = 0
    for pos in range(0, len(payload), CHUNK):
        n += 1
        frames[n] = encode(T_DATA, n, payload[pos:pos + CHUNK])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    hello = encode(T_START, 0)
    while True:
        sock.sendto(hello, peer)
        if recv_ack(sock, time.monotonic() + RTO) == 1:
            break

    confirmed = set()
    low, high = 1, 1                  # window covers [low, high)
    timer = time.monotonic() + RTO
    while low <= n:
        while high < low + window and high <= n:
            sock.sendto(frames[high], peer)
            high += 1
        seq = recv_ack(sock, timer)
        if seq is None:
            for s in range(low, high):
                if s not in confirmed:
                    sock.sendto(frames[s], peer)
            timer = time.monotonic() + RTO
        elif low <= seq < high:
            confirmed.add(seq)
            if low in confirmed:
                while low in confirmed:
                    confirmed.remove(low)
                    low += 1
                timer = time.monotonic() + RTO

    bye = encode(T_END, n + 1)
    limit = time.monotonic() + RTO
    while time.monotonic() < limit:
        sock.sendto(bye, peer)
        if recv_ack(sock, min(limit, time.monotonic() + 0.1)) == n + 1:
            break


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("receiver_ip")
    ap.add_argument("receiver_port", type=int)
    ap.add_argument("window_size", type=int)
    a = ap.parse_args()
    run(a.receiver_ip, a.receiver_port, a.window_size)
