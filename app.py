#!/usr/bin/env python3
import logging
import socket
import sys
import threading
import paramiko

logging.basicConfig()
logger = logging.getLogger()

if len(sys.argv) != 2:
    print("Need private host RSA key as argument.")
    sys.exit(1)

host_key = paramiko.RSAKey(filename=sys.argv[1])


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'publickey'

    def check_channel_exec_request(self, channel, command):
        # This is the command we need to parse
        channel.send("how dare you send me commands")
        self.event.set()
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True


class AcceptThread(threading.Thread):
    def __init__(self, client, addr):
        super().__init__()
        self.client = client
        self.address = addr

    def run(self):
        transport = paramiko.Transport(self.client)
        transport.set_gss_host(socket.getfqdn(""))
        transport.load_server_moduli()
        transport.add_server_key(host_key)
        server = Server()
        transport.start_server(server=server)

        # Wait 30 seconds for a command
        server.event.wait(30)
        channel = transport.accept(20)
        channel.setblocking(0)

        if channel is None:
            print("*** No channel.")
            sys.exit(1)

        if not server.event.is_set():
            print("*** Client never asked for a shell.")
            transport.close()

        channel.send("Welcome!!!\n")
        # channel.settimeout(1)
        while True:
            data = ''
            while True:
                try:
                    chunk = channel.recv(1024)
                except socket.timeout:
                    continue
                data += chunk.decode('utf-8')
                if not data:
                    break
                if data[-1] == "\n":
                    break
            if len(data) <= 1:
                transport.close()
                break
            channel.send("echo: {}>>".format(data))


def listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 2222))

    sock.listen(100)
    print('Listening to port 2222')

    # TODO after accepting, open new thread then continue accepting in main thread
    while True:
        client, addr = sock.accept()
        thread = AcceptThread(client, addr)
        thread.start()


while True:
    try:
        listener()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:
        logger.error(exc)