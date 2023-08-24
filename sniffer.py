import logging

# Turns off scapy warnings for macOS (need this before any scapy imports)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# If we wanted to be specific with our imports:
# from scapy.sendrecv import sniff
# from scapy.layers.inet import TCP
# from scapy.packet import Raw
from scapy.all import *
from parse import parse

def sniff_packet(encrypted: bool):
    # This filters for TCP segments with a destination port of 5000
    # that include the word "POST" in their decoded data section (aka payload)
    #
    # We are only looking for one packet: the username and password submission,
    # which will be found in an HTTP POST request
    if not encrypted:
        lfilter = lambda p: TCP in p and Raw in p and p[TCP].dport == 5000 and "POST" in p[Raw].load.decode()
        pcap = sniff(iface="lo0", lfilter=lfilter, count=1)
        request_str = pcap[0][Raw].load.decode()

        # The username and password are in the last line of the HTTP request
        # (the rest is the HTTP request line and headers)
        body = request_str.split("\n")[-1]

        # We know that the username and password fields have the HTML input names
        # of "username" and "password", but we could confirm this by inspecting the
        # HTML source of the home page
        login = parse("username={}&password={}", body)
        print("username = " + login[0])
        print("password = " + login[1])
    else:
        # If HTTPS is used, the entire HTTP request is encrypted with TLS, so you
        # will not be able to parse anything
        #
        # The request (in raw bytes) is printed out for demonstration
        lfilter = lambda p: TCP in p and Raw in p and p[TCP].dport == 5000
        pcap = sniff(iface="lo0", lfilter=lfilter, count=1)
        request = pcap[0][Raw].load
        print(request)

if __name__ == "__main__":
    if len(sys.argv) == 2 and "encrypt" in sys.argv[1]:
        sniff_packet(True)
    else:
        sniff_packet(False)
