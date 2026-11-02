import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

T_START, T_END, T_DATA, T_ACK = 0, 1, 2, 3


def build_ack(seq):
    hdr = PacketHeader(type=T_ACK, seq_num=seq, length=0, checksum=0)
    hdr.checksum = compute_checksum(bytes(hdr))
    return bytes(hdr)


def decode(raw):
    """Return (type, seq, body) for an intact packet, else None."""
    if len(raw) < 16:
        return None
    hdr = PacketHeader(raw[:16])
    body = raw[16:16 + hdr.length]
    if len(body) != hdr.length:
        return None
    given = hdr.checksum
    hdr.checksum = 0
    if compute_checksum(bytes(hdr) + body) != given:
        return None
    return hdr.type, hdr.seq_num, body


def run(ip, port, window):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    out = sys.stdout.buffer
    next_seq = 0          # 0 means "no connection yet"
    buffered = {}

    while True:
        raw, peer = sock.recvfrom(2048)
        got = decode(raw)
        if got is None:
            continue
        kind, seq, body = got

        if kind == T_START:
            if next_seq in (0, 1):
                next_seq = 1
                sock.sendto(build_ack(1), peer)
        elif next_seq == 0:
            continue
        elif kind == T_DATA:
            if seq >= next_seq + window:
                continue
            if seq >= next_seq:
                buffered[seq] = body
                while next_seq in buffered:
                    out.write(buffered.pop(next_seq))
                    next_seq += 1
                out.flush()
            sock.sendto(build_ack(seq), peer)    # ACK this exact packet
        elif kind == T_END and seq == next_seq:
            sock.sendto(build_ack(seq), peer)
            break


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("receiver_ip")
    ap.add_argument("receiver_port", type=int)
    ap.add_argument("window_size", type=int)
    a = ap.parse_args()
    run(a.receiver_ip, a.receiver_port, a.window_size)
