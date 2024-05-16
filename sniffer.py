import logging
import os
import sys

# Turns off scapy warnings for macOS (need this before any scapy imports)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from parse import parse, search
from scapy.all import (TCP, Packet, Raw, get_working_ifaces, rdpcap, sniff,
                       wrpcap)

stored_packet: Packet
payloads: list[bytes] = []
decoded_payload: str
encrypted: bool
file_upload: bool


def got_packet(packet: Packet) -> None:
    global stored_packet, payloads, decoded_payload
    if encrypted or file_upload:
        payloads.append(packet[Raw].load)
    else:
        decoded_payload = packet[Raw].load.decode()
        stored_packet = packet


def sniff_packets() -> None:
    # This gets the OS-specific name of the loopback interface (localhost)
    ifaces = get_working_ifaces()
    for iface in ifaces:
        if iface.ip == "127.0.0.1":
            loopback_iface = iface.name
            break

    if file_upload and sys.platform == "linux":
        count = 4
    elif file_upload:
        count = 2
    else:
        count = 1

    # This filters for TCP segments with a destination port of 5000. We are
    # only looking for one packet: the username and password submission,
    # which will be found in an HTTP POST request. Unless, of course, we
    # are using Safari, which for some unknown reason, sends 2 packets for
    # a simple POST request, even without a file upload.
    #
    # The destination host, which should be localhost, can be identified
    # with p[IP].dst (source host is p[IP].src). You can inspect the TCP
    # flags in p[TCP].flags which are bitwise ORed with each other, e.g.
    # p[TCP].flags & 0x08 equals 1 if the TCP PSH flag is set.
    #
    # Advanced: you can send raw IP packets or Ethernet frames with send()
    # and sendp() respectively:
    # https://scapy.readthedocs.io/en/latest/usage.html#sending-packets
    lfilter = lambda p: TCP in p and p[TCP].dport == 5000 and Raw in p
    sniff(iface=loopback_iface, lfilter=lfilter, prn=got_packet, count=count)

    if not encrypted:
        # If file uploading is enabled, we want to capture the first 2 packets,
        # since multipart/form-data sometimes sends the form arguments after the
        # packet with the HTTP POST request line. However, on Linux, packets on
        # localhost are duplicated, so we end up needing to capture 4 packets,
        # disregarding the 2nd and 4th packets.
        if file_upload:
            payload = payloads[0]
            if b"Content-Disposition" not in payload:
                if sys.platform == "linux":
                    second_payload = payloads[2]
                else:
                    second_payload = payloads[1]

                # Following this Content-Type header is 2 newlines followed by
                # the beginning of the uploaded file. This is where you'd extract
                # the file, assuming you have all of the packets up to the HTTP
                # 200 response sent by the server. In the case of a file download,
                # after the last header followed by a newline is where the file
                # data starts.
                #
                # It is the second overall Content-Type header, the first being
                # Content-Type: multipart/form-data
                index = second_payload.index(b"Content-Type")
                payload += second_payload[:index]
                request_str = payload.decode()
            else:
                # Since there are two Content-Type headers present, we need to
                # find the index of the first match, then look for the second
                # match in the substring following the first match.
                first_index = payload.index(b"Content-Type")
                first_index += len("Content-Type: multipart/form-data")
                index = payload[first_index:].index(b"Content-Type")
                request_str = payload[: first_index + index].decode()
            # We need to get the boundary because the username and/or password
            # could have hyphens in them, which would break search()
            (boundary,) = search(
                "Content-Type: multipart/form-data; boundary={}\n",
                request_str,
                case_sensitive=True,
            )
            (username,) = search(
                'Content-Disposition: form-data; name="username"{}--' + boundary,
                request_str,
                case_sensitive=True,
            )
            (password,) = search(
                'Content-Disposition: form-data; name="password"{}--' + boundary,
                request_str,
                case_sensitive=True,
            )
            username = str(username)
            password = str(password)
            print(f"username = {username.strip()}")
            print(f"password = {password.strip()}")
        else:
            # Since the Content-Type is application/x-www-form-urlencoded, the
            # username and password are in the last line of the HTTP request
            # (the rest is the HTTP request line, headers, and a newline).
            body = decoded_payload.split("\n")[-1]

            # We know that the username and password fields have the HTML input
            # names of "username" and "password", but we could confirm this by
            # inspecting the HTML source of the home page.
            #
            # This will not capture Safari form data properly, since it's sent
            # in a second packet.
            login = parse("username={}&password={}", body, case_sensitive=True)
            print(f"username = {login[0]}")
            print(f"password = {login[1]}")
            print("\n--------------------------------------------------\n")

            # Write the packet to a pcap file then read from the file and print
            # the payload
            wrpcap("data.pcap", [stored_packet])
            packets = rdpcap("data.pcap")
            print(packets[0][Raw].load.decode())
    else:
        # If HTTPS is used, the entire HTTP request is encrypted with TLS, so you
        # will not be able to parse anything.
        #
        # The request (in raw bytes) is printed out for demonstration.
        print(payloads[0].hex())


if __name__ == "__main__":
    var = os.getenv("FILE_UPLOAD")
    if var is not None and var == "1":
        file_upload = True
    else:
        file_upload = False

    if len(sys.argv) == 2 and "encrypt" in sys.argv[1]:
        encrypted = True
    else:
        encrypted = False
    sniff_packets()
