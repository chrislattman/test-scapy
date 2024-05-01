import logging
import os
import sys

# Turns off scapy warnings for macOS (need this before any scapy imports)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from parse import parse, search
from scapy.all import TCP, Raw, get_working_ifaces, sniff

var = os.getenv("FILE_UPLOAD")
if var and var == "1":
    file_upload = True
else:
    file_upload = False


def sniff_packet(encrypted: bool):
    # This gets the OS-specific name of the loopback interface (localhost)
    ifaces = get_working_ifaces()
    for iface in ifaces:
        if iface.ip == "127.0.0.1":
            loopback_iface = iface.name
            break

    if file_upload:
        count = 4
    else:
        count = 1

    if not encrypted:
        # This filters for TCP segments with a destination port of 5000
        # that include the word "POST" in their decoded data section (aka payload)
        #
        # We are only looking for one packet: the username and password submission,
        # which will be found in an HTTP POST request.
        #
        # If file uploading is enabled, we want to capture the first 2 packets,
        # since multipart/form-data sometimes sends the form arguments after the
        # packet with the HTTP POST request line. However, packets on localhost are
        # duplicated, so we end up needing to capture 4 packets, discarding the 2nd
        # and 4th packets (unless on macOS).
        if file_upload:
            lfilter = (
                lambda p: TCP in p
                and Raw in p
                and p[TCP].dport == 5000
            )
        else:
            lfilter = (
                lambda p: TCP in p
                and Raw in p
                and p[TCP].dport == 5000
                and "POST" in p[Raw].load.decode()
            )
        pcap = sniff(iface=loopback_iface, lfilter=lfilter, count=count)
        if file_upload:
            payload = pcap[0][Raw].load
            if b"Content-Disposition" not in payload:
                if sys.platform == "darwin":
                    second_payload = pcap[1][Raw].load
                else:
                    second_payload = pcap[2][Raw].load
                # Following this header is 2 newlines followed by the beginning
                # of the uploaded file. This is where you'd extract the file,
                # assuming you have all of the packets up to the HTTP 200 response
                # sent by the server.
                #
                # It is the second overall Content-Type header, the first being
                # Content-Type: multipart/form-data
                index = second_payload.index(b"Content-Type")
                payload += second_payload[:index]
            else:
                # Since there are two Content-Type headers present, we need to
                # find the index of the first match, then look for the second match
                # in the substring following the first match
                first_index = payload.index(b"Content-Type")
                first_index += len("Content-Type: multipart/form-data")
                index = payload[first_index:].index(b"Content-Type")
                payload = payload[:first_index + index]
            request_str = payload.decode()
            boundary, = search("Content-Type: multipart/form-data; boundary={}\n", request_str)
            username, = search('Content-Disposition: form-data; name="username"{}--' + boundary, request_str)
            password, = search('Content-Disposition: form-data; name="password"{}--' + boundary, request_str)
            print(f"username = {username.strip()}")
            print(f"password = {password.strip()}")
        else:
            request_str = pcap[0][Raw].load.decode()
            # The username and password are in the last line of the HTTP request
            # (the rest is the HTTP request line and headers)
            body = request_str.split("\n")[-1]

            # We know that the username and password fields have the HTML input names
            # of "username" and "password", but we could confirm this by inspecting the
            # HTML source of the home page
            login = parse("username={}&password={}", body)
            print(f"username = {login[0]}")
            print(f"password = {login[1]}")
    else:
        # If HTTPS is used, the entire HTTP request is encrypted with TLS, so you
        # will not be able to parse anything
        #
        # The request (in raw bytes) is printed out for demonstration
        lfilter = lambda p: TCP in p and Raw in p and p[TCP].dport == 5000
        pcap = sniff(iface=loopback_iface, lfilter=lfilter, count=count)
        request = pcap[0][Raw].load
        print(request)


if __name__ == "__main__":
    if len(sys.argv) == 2 and "encrypt" in sys.argv[1]:
        sniff_packet(True)
    else:
        sniff_packet(False)
