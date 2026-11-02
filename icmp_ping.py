import socket
import struct
import time
import os
import sys
import select

def checksum(data):
    """Calculate the Internet checksum required by ICMP."""
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xffff) + (total >> 16)

    return (~total) & 0xffff


def ping(destination, sequence, timeout=2):
    """Send one ICMP Echo Request and wait for an Echo Reply."""
    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Could not resolve host: {destination}")
        return False

    icmp_type = 8  # Echo Request
    code = 0
    packet_id = os.getpid() & 0xffff
    header = struct.pack("!BBHHH", icmp_type, code, 0, packet_id, sequence)
    payload = b"Python ICMP Ping"
    packet_checksum = checksum(header + payload)
    header = struct.pack(
        "!BBHHH", icmp_type, code, packet_checksum, packet_id, sequence
    )
    packet = header + payload

    try:
        # On Windows, run the terminal as Administrator to use raw sockets.
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(timeout)
            start = time.perf_counter()
            sock.sendto(packet, (destination_ip, 1))

            while True:
                try:
                    reply, address = sock.recvfrom(1024)
                except socket.timeout:
                    print(f"Request timed out for {destination} ({destination_ip})")
                    return False

                # IPv4 header is normally 20 bytes, but may be longer with options.
                ip_header_length = (reply[0] & 0x0f) * 4
                icmp_header = reply[ip_header_length:ip_header_length + 8]
                if len(icmp_header) < 8:
                    continue

                reply_type, reply_code, _, reply_id, reply_sequence = struct.unpack(
                    "!BBHHH", icmp_header
                )

                # ICMP Echo Reply is type 0; match our identifier and sequence.
                if reply_type == 0 and reply_id == packet_id and reply_sequence == sequence:
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    print(
                        f"Reply from {address[0]}: bytes={len(reply) - ip_header_length} "
                        f"time={elapsed_ms:.2f} ms TTL={reply[8]}"
                    )
                    return True

    except PermissionError:
        print("Permission denied. On Windows, run Command Prompt/Terminal as Administrator.")
        return False
    except OSError as error:
        print(f"Socket error: {error}")
        print("Try running the terminal as Administrator and check your firewall.")
        return False


def main():
    destination = input("Enter host or IP address (example: 8.8.8.8): ").strip()
    if not destination:
        print("Host/IP address cannot be empty.")
        sys.exit(1)

    count_text = input("Number of ping requests [4]: ").strip()
    count = int(count_text) if count_text else 4
    if count < 1:
        print("Number of requests must be at least 1.")
        sys.exit(1)

    print(f"\nPinging {destination} with Python ICMP Ping:\n")
    sent = 0
    received = 0

    for sequence in range(1, count + 1):
        sent += 1
        if ping(destination, sequence):
            received += 1
        if sequence < count:
            time.sleep(1)

    lost = sent - received
    loss_percent = (lost / sent) * 100
    print("\nPing statistics:")
    print(f"    Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_percent:.0f}% loss)")


if __name__ == "__main__":
    main()
