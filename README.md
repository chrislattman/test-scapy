# About

This is an example of how to extract login credentials from an HTTP POST request over an insecure connection. If using HTTPS, this would not work since payloads are encrypted with TLS. (This is a reminder to always use HTTPS when sending data over the Internet!)

Test this by running

```
pip3 install -r requirements.txt
python3 app.py
```

Then in a second terminal, run

```
python3 sniffer.py
```

- Note: on Linux, you will have to run `sudo -E python3 sniffer.py`

Visit http://127.0.0.1:5000 on a web browser, and enter any login credentials (it doesn't matter what they are). Once you hit "Submit", you will be shown a success page. Check the second terminal and you should see the credentials you just entered.

If you want to see what encrypted data looks like, add `encrypt` as an argument to both python3 commands, and run them again, e.g.

```
python3 app.py encrypt
```

and

```
python3 sniffer.py encrypt
```

- The Linux note applies here as well

If you want to test viewing decrypted HTTPS traffic, install [`mitmproxy`](https://mitmproxy.org/) preferably on some other computer than the device you're testing.

- mitmproxy works by routing all HTTP/S (and WebSocket) traffic through a proxy that you control
- This means any TLS handshake normally done between your device and a website is split up between your device and the mitmproxy server, and the mitmproxy server and the website (hence the mitm- prefix, meaning "man-in-the-middle")
- It gives you the ability to see decrypted HTTPS traffic in `tcpdump`-like fashion with `mitmdump` or on a webpage with `mitmweb`
- In order for this to work:
    - You will have to manually configure the HTTP proxy on your device to forward its HTTP/S traffic to the mitmproxy server
    - You may need to install mitmproxy's valid CA (root) certificate on your device
- While mitmproxy is a handy tool, it's defeated by client certificate pinning, where the server expects a certain certificate from the client (this is rare)
