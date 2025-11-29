import socket

def scan_port(host, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))

        try:
            banner = s.recv(1024).decode(errors="ignore")
        except:
            banner = None

        s.close()
        return banner
    except:
        return None
