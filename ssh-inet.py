#!/usr/bin/env python3
# coding: utf-8

import os
import struct

import tornado.ioloop
import tornado.iostream
import socket

#######################
# from 
# http://gnuradio.org/redmine/projects/gnuradio/repository/changes/gnuradio-examples/python/digital/tunnel.py?rev=e692e71305ecd71d3681fe37f3d76f350d67e276

# Linux specific...
# TUNSETIFF ifr flags from <linux/tun_if.h>

IFF_TUN		= 0x0001   # tunnel IP packets
IFF_TAP		= 0x0002   # tunnel ethernet frames
IFF_NO_PI	= 0x1000   # don't pass extra packet info | размер ifreq (ifs) может быть меньше  

def open_tun_interface():
    from fcntl import ioctl
    
    mode = IFF_TUN | IFF_NO_PI
    TUNSETIFF = 0x400454ca

    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifs = ioctl(tun, TUNSETIFF, struct.pack("16sH", b"ssh-inet-tun%d", mode))
    ifname = ifs[:16].strip(b"\x00").decode()
    return tun, ifname

#######################
# pyiface
# Очень неудобно работать с ctypes

def pyiface_open_tun_interface():
    import pyiface as pi
    
    IFF_TUN = 0x0001
    
    ifr = pi.iface.ifreq()
    name = "tun3"
    ifr.ifr_name = ifr.ifr_name.__class__(bytes(name, "ascii"))
    ifr.ifr_flags = IFF_TUN

#######################

# из test_sendfile.py
def make_tcp_server(handle_stream):
    from tornado.tcpserver import TCPServer
    
    class Server(TCPServer):
        pass
    Server.handle_stream = handle_stream
        
    # max_buffer_size - иначе ошибка "Reached maximum read buffer size" на
    # больших чтениях
    return Server(max_buffer_size=404857600)

def start_tcp_server(handle_stream, port):
    server = make_tcp_server(handle_stream)
    server.listen(port)
        
    def handle_signal(sig, frame):
        io_loop.add_callback(io_loop.stop)
    
    import signal
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, handle_signal)

def connect(host, port, callback):
    stream = tornado.iostream.IOStream(socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    def on_connection():
        assert not stream._connecting
        # успех => не нужен
        stream.set_close_callback(None)
        
        callback(stream)
    stream.connect((host, port), on_connection)
    assert stream._connecting
    
    def on_close():
        callback(None)
    stream.set_close_callback(on_close)

import argparse
def make_struct(**kwargs):
    return argparse.Namespace(**kwargs)

import subprocess
import shlex
def call_cmd(cmd):
    #print(cmd)
    return subprocess.call(shlex.split(cmd))

def main():
    import sys
    
    self_options, ssh_options = [], sys.argv[1:]
    try:
        idx = ssh_options.index("--")
        self_options, ssh_options = ssh_options[:idx], ssh_options[idx+1:]
    except ValueError:
        pass
    
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--remote_port', default=None,
        type=int, 
        help='remote client mode',
    )
    args = parser.parse_args(self_options)
    
    # чтобы без root'а запускать: sudo setcap cap_net_admin+eip
    tun, ifname = open_tun_interface()

    local_ip  = "10.0.0.1"
    remote_ip = "10.0.0.2"

    is_local = args.remote_port is None
    this_ip = local_ip if is_local else remote_ip
    that_ip = remote_ip if is_local else local_ip
        
    call_cmd("ip address add %(this_ip)s/30 peer %(that_ip)s dev %(ifname)s" % locals())
    call_cmd("ip link set dev %(ifname)s up" % locals())

    if is_local:
        # по умолчанию в ядре маршрутизация выключена, см. devinet.c, ipv4_devconf_dflt
        call_cmd("sysctl -q net.ipv4.ip_forward=1")

        setup_masquerade()
    else:
        call_cmd("ip route add default dev %(ifname)s" % locals())
        append_dns_nameserver(ifname)

    async_operation = True
    if async_operation:
        io_loop = tornado.ioloop.IOLoop.instance()

        tun_strm = tornado.iostream.PipeIOStream(tun)

        tun_socket = make_struct(
            tun = tun_strm,
            socket = None,
        )
        
        def on_stream_end():
            print("Stream is closed")
            io_loop.stop()
        
        # 1 тоннель
        def write_to_socket(bs):
            if bs:
                print("tun => socket")
                
                strm = tun_socket.socket
                if strm:
                    strm.write(bs)
                else:
                    print("No socket, dropping")
        
        def handle_tun_read(bs):
            write_to_socket(bs)
        def handle_tun_read_end(bs):
            write_to_socket(bs)
            
            on_stream_end()
            assert False, "Client tunnel fd is closed"
        tun_strm.read_until_close(handle_tun_read_end, streaming_callback=handle_tun_read)
        
        # 2 сокет
        def write_to_tun(bs):
            print("socket => tun")
            
            if bs:
                tun_socket.tun.write(bs)
                
        def start_proxying(stream):
            tun_socket.socket = stream
            
            def handle_socket_read(bs):
                write_to_tun(bs)
            def handle_socket_read_end(bs):
                write_to_tun(bs)
                on_stream_end()
            stream.read_until_close(handle_socket_read_end, streaming_callback=handle_socket_read)

        if is_local:
            def handle_stream(self, stream, address):
                if tun_socket.socket is None:
                    start_proxying(stream)
                else:
                    print("Needless connection, dropping")
                    stream.close()
            start_tcp_server(handle_stream, 1080)
        else:
            def on_connection(stream):
                start_proxying(stream)
            connect("localhost", args.remote_port, on_connection)
        
        io_loop.start()
    else:
        # почему-то в этом случае только 1-й байт пинга считывается 
        while True:
            s = os.read(tun, 1)
            print("!", s)

        os.close(tun)

def setup_masquerade():
    subnet = "10.0.0.0/30"
    
    need_masquerade = True
    txt = subprocess.check_output(shlex.split("iptables -t nat -n -L"))
    for line in txt.splitlines():
        line = line.decode("utf-8").split()
        if "ssh-inet" in line and subnet in line:
            need_masquerade = False
            break
        
    if need_masquerade:
        # "TRICKY" удалить именно это правило можно по его номеру:
        # $ iptables -t nat -n -L --line-numbers
        # $ iptables -t nat -D POSTROUTING 1
        call_cmd('''iptables -t nat -A POSTROUTING -s %(subnet)s -j MASQUERADE -m comment --comment "ssh-inet"''' % locals())

def append_dns_nameserver(ifname):        
    # эквивалентно:
    # echo "nameserver 8.8.8.8" | resolvconf -a $ifname
    
    # удалить можно с помощью команды
    # resolvconf -d $ifname
    
    # Google DNS
    nameserver = "8.8.8.8"
    with subprocess.Popen(shlex.split("resolvconf -a %s" % ifname), stdin=subprocess.PIPE) as p:
        p.communicate(input=bytes("nameserver %s" % nameserver, "ascii"))
        
if __name__ == "__main__":
    if False:
        main()
        
    if False:
        #call_cmd("ssh bbl-ott-node02-01-77 sudo ls /root")
        #setup_masquerade()
        append_dns_nameserver("tun1")
        