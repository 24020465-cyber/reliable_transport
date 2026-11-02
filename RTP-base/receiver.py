import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
HEADER_LEN = 16


def make_ack(seq_num):
    header = PacketHeader(type=ACK, seq_num=seq_num, length=0)
    header.checksum = compute_checksum(header)
    return bytes(header)


def read_packet(raw):
    """Return (type, seq_num, payload), or None if the packet is damaged."""
    if len(raw) < HEADER_LEN:
        return None
    header = PacketHeader(raw[:HEADER_LEN])
    payload = raw[HEADER_LEN:HEADER_LEN + header.length]
    if len(payload) != header.length:
        return None
    received = header.checksum
    header.checksum = 0
    if compute_checksum(bytes(header) + payload) != received:
        return None
    return header.type, header.seq_num, payload


def receiver(receiver_ip, receiver_port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))
    out = sys.stdout.buffer

    expected = None   # next in-order seq_num; None until START arrives
    held = {}         # out-of-order payloads waiting for the gap to fill

    while True:
        raw, addr = sock.recvfrom(2048)
        pkt = read_packet(raw)
        if pkt is None:
            continue                      # corrupted: drop, send no ACK
        kind, seq, payload = pkt

        if kind == START:
            if expected is None or expected == 1:
                expected = 1
                sock.sendto(make_ack(1), addr)
            continue                      # START in mid-connection: ignore
        if expected is None:
            continue

        if kind == DATA:
            if seq >= expected + window_size:
                continue                  # outside the window
            if seq >= expected:
                held[seq] = payload
                while expected in held:
                    out.write(held.pop(expected))
                    expected += 1
                out.flush()
            sock.sendto(make_ack(expected), addr)
        elif kind == END:
            if seq == expected:
                sock.sendto(make_ack(seq + 1), addr)
                break
            sock.sendto(make_ack(expected), addr)   # data still missing


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()
    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
