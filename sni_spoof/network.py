from __future__ import annotations

import socket


def get_default_interface_ipv4(addr: str = "8.8.8.8") -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((addr, 53))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def get_default_interface_ipv6(addr: str = "2001:4860:4860::8888") -> str:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.connect((addr, 53))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def configure_keepalive(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    for option_name, value in (("TCP_KEEPIDLE", 11), ("TCP_KEEPINTVL", 2), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, option_name, None)
        if option is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError:
            continue


def build_ipv4_filter(interface_ipv4: str, connect_ip: str) -> str:
    return (
        "tcp and "
        f"((ip.SrcAddr == {interface_ipv4} and ip.DstAddr == {connect_ip}) or "
        f"(ip.SrcAddr == {connect_ip} and ip.DstAddr == {interface_ipv4}))"
    )
