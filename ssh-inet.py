#!/usr/bin/env python3
# coding: utf-8

import os
import struct
import socket
import sys
import argparse
import zipfile

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

def make_struct(**kwargs):
    return argparse.Namespace(**kwargs)

import subprocess
import shlex
def call_cmd(cmd):
    log(cmd)
    return subprocess.call(shlex.split(cmd))

def main():
    
    # чтобы без root'а запускать: sudo setcap cap_net_admin+eip
    tun, ifname = open_tun_interface()

    local_ip  = "10.0.0.1"
    remote_ip = "10.0.0.2"

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
        
        def start_tcp_server(handle_stream, port):
            server = make_tcp_server(handle_stream)
            server.listen(port)
                
            def handle_signal(sig, frame):
                io_loop.add_callback(io_loop.stop)
            
            import signal
            for sig in [signal.SIGINT, signal.SIGTERM]:
                signal.signal(sig, handle_signal)

        tun_strm = tornado.iostream.PipeIOStream(tun)

        tun_socket = make_struct(
            tun = tun_strm,
            socket = None,
        )
        
        def on_stream_end():
            log("Stream is closed")
            io_loop.stop()
        
        # 1 тоннель
        def write_to_socket(bs):
            if bs:
                log("tun => socket")
                
                strm = tun_socket.socket
                if strm:
                    strm.write(bs)
                else:
                    log("No socket, dropping")
        
        def handle_tun_read(bs):
            write_to_socket(bs)
        def handle_tun_read_end(bs):
            write_to_socket(bs)
            
            on_stream_end()
            assert False, "Client tunnel fd is closed"
        tun_strm.read_until_close(handle_tun_read_end, streaming_callback=handle_tun_read)
        
        # 2 сокет
        def write_to_tun(bs):
            log("socket => tun")
            
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
                    log("Needless connection, dropping")
                    stream.close()
            port = 1080
            start_tcp_server(handle_stream, port)
            
            # меняем назад uid, если под sudo, чтобы не смутить ssh
            if "SUDO_UID" in os.environ:
                os.setresuid(int(os.environ["SUDO_UID"]), -1, -1)
                # странно, почему-то ssh вылетал с ошибкой "нельзя выполнить setresgid()"
                # теперь вот перестал
                orig_gid = int(os.environ["SUDO_GID"])
                os.setresgid(orig_gid, orig_gid, orig_gid)
            
            # запускаем удаленно скрипт
            python_exec = args.remote_python_binary if args.remote_python_binary else "python3"
            script = args.remote_si if args.remote_si else "-"
            verbose = " --verbose" if args.verbose else "" 
            cmd = ["ssh"] + ssh_options + shlex.split("-R %(port)s:localhost:%(port)s sudo %(python_exec)s %(script)s%(verbose)s --remote_port %(port)s --" % locals())
            log(cmd)
            
            import tornado.process as tornado_process
            Subprocess = tornado_process.Subprocess
            
            if args.remote_si:
                ssh_proc = Subprocess(cmd)
            else:
                ssh_proc = Subprocess(cmd, stdin=subprocess.PIPE)
                
                with open(__file__, "rb") as f:
                    this_text = f.read()
                # :TODO: если на той стороне не скачают, то будет затык
                # => лучше асинхронно сделать
                ssh_proc.stdin.write(this_text)
                ssh_proc.stdin.close()
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

def setup_zip_py_path(zf):
    import imp
    class MemoryZipImporter:
        def __init__(self, zf):
            self.zf = zf
            self.modules = {}
            
            for info in zf.infolist():
                filename = info.filename
                head, sep, tail = filename.rpartition(".")
                # поддержка только py-модулей, ради простоты
                if tail == "py":
                    head_head, init_sep, tail = head.rpartition("/__init__")
                    if init_sep and not tail:
                        # это __init__.py
                        head = head_head
                    self.modules[head.replace("/", ".")] = filename
                    
            #print(self.modules)
            
        def find_module(self, fullname, path=None):
            return self if fullname in self.modules else None
        
        def load_module(self, fullname):
            try:
                mpath = self.modules[fullname]
            except:
                raise ImportError(fullname)
            
            mod = sys.modules.setdefault(fullname, imp.new_module(fullname))
            mod.__file__ = "MemoryZipImporter:%(mpath)s" % locals()
            # :TRICKY: для вложенных модулей на модуль родителя нужно проставить
            # __path__ (придет аргумент path в load_module), иначе не загрузятся
            mod.__path__ = [mpath]
            
            txt = zf.read(mpath)
            #exec txt in mod.__dict__
            code = compile(txt, mod.__file__, "exec")
            exec(code, mod.__dict__)

            return mod
        
    z_importer = MemoryZipImporter(zf)
    sys.meta_path.insert(0, z_importer)

#######################

def parse_args():
    self_options, ssh_options = [], sys.argv[1:]
    try:
        idx = ssh_options.index("--")
        self_options, ssh_options = ssh_options[:idx], ssh_options[idx+1:]
    except ValueError:
        pass

    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        '-v', '--verbose', default=False,
        action='store_true',
    )

    parser.add_argument(
        '--remote_si', default=None,
        help='remote ssh-inet peer to communicate instead of copying this one',
    )
    
    parser.add_argument(
        '--remote_port', default=None,
        type=int, 
        help='remote client mode',
    )
    
    parser.add_argument(
        '--remote_python_binary', default=None,
        help='remote tornado pythonpath',
    )
    
    return parser.parse_args(self_options), ssh_options

args, ssh_options = parse_args()
is_local = args.remote_port is None

def log(msg, *msgs, is_error=False):
    if args.verbose or is_error:
        prefix = "local:" if is_local else "remote:"
        print(prefix, msg, *msgs)

if is_local and not ssh_options:
    log("no server to connect", is_error=True)
    sys.exit(1)

#tornado_zip = ""

# загрузка зависимостей
dep_zf = None
if "tornado_zip" in dir():
    import base64
    tornado_zip = base64.b64decode(bytes(tornado_zip, "ascii"))
    
    import io
    dep_zf = zipfile.ZipFile(io.BytesIO(tornado_zip))
elif is_local:
    # :TODO: переделать через ключ --tornado_zip <path>
    local_zip_fname = os.path.join(os.path.dirname(__file__), "tornado322.zip")
    dep_zf = zipfile.ZipFile(local_zip_fname)
    
if dep_zf:
    setup_zip_py_path(dep_zf)

import tornado.ioloop
import tornado.iostream

#######################
        
if __name__ == "__main__":
    if False:
        main()
        
    if False:
        #call_cmd("ssh 192.168.1.2 sudo ls /root")
        #setup_masquerade()
        append_dns_nameserver("tun1")
        
    if True:
        import sys, os
        #print(os.environ["PS1"], "!")
        #ret = call_cmd("/bin/bash")
        #ret = call_cmd("mysql -u root")
        ret = call_cmd("ssh 192.168.1.2 sudo bash")
        print("!", ret)
        
    if False:
        zip_path = "/home/ilya/opt/programming/ssh-inet/tornado322.zip"
        
        with zipfile.ZipFile(zip_path) as zf:
            setup_zip_py_path(zf)
            
            import tornado.ioloop
            import tornado
            import tornado.ioloop
            import tornado.ioloop
        