import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

START, END, DATA, ACK = 0, 1, 2, 3
HEADER_LEN = 16
MAX_PAYLOAD = 1472 - HEADER_LEN   # 1456 bytes of data per packet
TIMEOUT = 0.5


def make_packet(kind, seq, payload=b""):
    header = PacketHeader(type=kind, seq_num=seq, length=len(payload))
    header.checksum = compute_checksum(bytes(header) + payload)
    return bytes(header) + payload


def ack_number(raw):
    """Return the seq_num of a valid ACK packet, otherwise None."""
    if len(raw) < HEADER_LEN:
        return None
    header = PacketHeader(raw[:HEADER_LEN])
    body = raw[HEADER_LEN:HEADER_LEN + header.length]
    received = header.checksum
    header.checksum = 0
    if compute_checksum(bytes(header) + body) != received:
        return None
    if header.type != ACK:
        return None
    return header.seq_num


def wait_for_ack(sock, deadline):
    """Return the next valid ACK's seq_num, or None if the deadline passes."""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        readable, _, _ = select.select([sock], [], [], remaining)
        if not readable:
            return None
        raw, _ = sock.recvfrom(2048)
        seq = ack_number(raw)
        if seq is not None:
            return seq


def sender(receiver_ip, receiver_port, window_size):
    dest = (receiver_ip, receiver_port)
    data = sys.stdin.buffer.read()
    chunks = [data[i:i + MAX_PAYLOAD] for i in range(0, len(data), MAX_PAYLOAD)]
    last = len(chunks)                    # DATA seq_nums are 1 .. last
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send_data(seq):
        sock.sendto(make_packet(DATA, seq, chunks[seq - 1]), dest)

    # 1) Handshake: START has seq 0, its ACK carries seq 1.
    start_pkt = make_packet(START, 0)
    while True:
        sock.sendto(start_pkt, dest)
        if wait_for_ack(sock, time.monotonic() + TIMEOUT) == 1:
            break

    # 2) Sliding window. base = oldest unacked packet, nxt = next to send.
    base = 1
    nxt = 1
    deadline = time.monotonic() + TIMEOUT
    while base <= last:
        while nxt < base + window_size and nxt <= last:
            send_data(nxt)
            nxt += 1
        ack = wait_for_ack(sock, deadline)
        if ack is None:                   # timer expired: resend whole window
            for seq in range(base, nxt):
                send_data(seq)
            deadline = time.monotonic() + TIMEOUT
        elif base < ack <= nxt:           # window moved forward
            base = ack
            deadline = time.monotonic() + TIMEOUT

    # 3) Teardown: END has seq last+1, its ACK carries last+2.
    end_pkt = make_packet(END, last + 1)
    stop_at = time.monotonic() + TIMEOUT
    while time.monotonic() < stop_at:
        sock.sendto(end_pkt, dest)
        if wait_for_ack(sock, min(stop_at, time.monotonic() + 0.1)) == last + 2:
            break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
