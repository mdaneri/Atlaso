"""Bounded passive IPv4 ingress proof using the Linux packet socket interface."""

from __future__ import annotations

import ipaddress
import socket
import struct
import time


def matches_request(packet: bytes, packet_type: int, source: bytes, target: bytes, source_port: int) -> bool:
    """Match one unfragmented incoming unicast NTP query with its unique tuple.

    Args:
        packet: Cooked AF_PACKET IPv4 bytes without the link-layer header.
        packet_type: Linux packet classification; only PACKET_HOST is accepted.
        source: Admitted peer IPv4 address in packed form.
        target: Admitted appliance IPv4 address in packed form.
        source_port: Unique UDP source port allocated for this one query.
    """
    if packet_type != 0 or len(packet) < 76 or packet[0] >> 4 != 4:
        return False
    header = (packet[0] & 15) * 4
    if (header < 20 or len(packet) < header + 56 or packet[9] != 17
            or struct.unpack_from("!H", packet, 2)[0] != header + 56
            or struct.unpack_from("!H", packet, 6)[0] & 0x3FFF
            or packet[12:16] != source or packet[16:20] != target):
        return False
    port, destination, length = struct.unpack_from("!HHH", packet, header)
    return (port == source_port and destination == 123 and length == 56
            and packet[header + 8] & 7 == 3 and packet[header + 48:header + 56] != bytes(8))


def capture(source: str, target: str, source_port: int) -> None:
    """Observe one query without transmitting, changing filters or retaining bytes.

    Args:
        source: Admitted numeric peer address.
        target: Admitted numeric appliance address.
        source_port: Unique query source port.
    """
    source_bytes = ipaddress.IPv4Address(source).packed
    target_bytes = ipaddress.IPv4Address(target).packed
    if type(source_port) is not int or not 1 <= source_port <= 65535:
        raise ValueError("ntp_capture_port_invalid")
    # SOCK_DGRAM strips the hardware header. No bind, promiscuous membership,
    # send operation or firewall mutation is used; only local unicast ingress
    # with the exact peer/address/UDP tuple can establish delivery.
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800)) as observer:
        deadline = time.monotonic() + 8
        consumed = 0
        print("capture_ready", flush=True)
        for _ in range(4096):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            observer.settimeout(remaining)
            try:
                packet, address = observer.recvfrom(65535)
            except TimeoutError:
                break
            consumed += len(packet)
            if consumed > 4 * 1024**2:
                raise RuntimeError("ntp_capture_byte_budget_exceeded")
            if matches_request(packet, address[2], source_bytes, target_bytes, source_port):
                if time.monotonic() > deadline:
                    break
                print("request_delivered", flush=True)
                return
    raise RuntimeError("ntp_capture_request_not_observed")
