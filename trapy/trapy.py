import socket
from .utils import parse_address
import logging
import random
from .packet import *
from .timer import Timer

logger = logging.getLogger('serve-file')

IP_HEADER_SIZE = 20
PRO_HEADER_SIZE = 20
HEADER_SIZE = 40
DATA_SIZE = 1024
SEGMENT_SIZE = DATA_SIZE + HEADER_SIZE
WINDOW_SIZE = 8

class Conn:
    def __init__(self, sock = None):
        self.source_address = None
        self.destination_address = None
        self.socket = sock
        self.seq_num = 0
        self.ack_num = 0
        self.ws = WINDOW_SIZE
        self.timer = Timer()
        if not self.socket:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.socket.settimeout(0)
        self.cack = 0

    def setSourceAddress(self, address):
        self.source_address = address
    def setDestinationAddress(self, address):
        self.destination_address = address

class ConnException(Exception):
    pass


def listen(address: str) -> Conn:
    conn = Conn()
    conn.setSourceAddress(parse_address(address))

    conn.socket.bind(conn.source_address)
    return conn


def accept(conn) -> Conn:
    conn.timer.start()
    conn.timer.mark()
    while True:
        if conn.timer.wait(20): raise KeyboardInterrupt()###########

        try: address, pro, data = __read__(conn)
        except: continue

        if not is_syn(pro) or ack_number(pro) != 1:
            continue

        conn.timer.stop()

        newConn = Conn()
        newConn.setSourceAddress(newConn.socket.getsockname())
        newConn.setDestinationAddress(address)
        newConn.seq_num = random.randint(2, 1<<20)
        newConn.ack_num = sequence_number(pro) + 1

        HOST, PORT = newConn.source_address
        host, port = newConn.destination_address
        package = make_pro_header(PORT, port, newConn.seq_num, newConn.ack_num, newConn.ws, ACK=1, SYN=1)

        newConn.timer.mark()
        while True:
            if not newConn.timer.running() or newConn.timer.timeout():
                newConn.socket.sendto(package, newConn.destination_address)
                newConn.setSourceAddress(newConn.socket.getsockname())
                newConn.timer.start()

            if newConn.timer.wait(180):
                newConn.timer.stop()
                raise ConnException()

            try: _, pro, data = __read__(newConn)
            except: continue

            if sequence_number(pro) != newConn.ack_num or ack_number(pro) != newConn.seq_num + 1\
                    or not is_ack(pro):
                continue

            newConn.seq_num = ack_number(pro)
            newConn.ack_num = sequence_number(pro) + 1
            newConn.timer.stop()

            return newConn

def dial(address) -> Conn:
    conn = Conn()
    conn.setSourceAddress(conn.socket.getsockname())
    conn.setDestinationAddress(parse_address(address))
    conn.seq_number = random.randint(2, 1<<20)

    HOST, PORT = conn.source_address
    host, port = conn.destination_address

    package = make_pro_header(PORT, port, conn.seq_num, 1, 0, SYN=1)

    conn.timer.mark()

    while True:
        if not conn.timer.running() or conn.timer.timeout():
            conn.socket.sendto(package, conn.destination_address)
            conn.timer.start()

        if conn.timer.wait(180):
            conn.timer.stop()
            raise ConnException()

        try: address, pro, data = __read__(conn)
        except: continue

        if is_ack(pro) and is_syn(pro) and ack_number(pro) == conn.seq_num + 1:
            conn.seq_num = ack_number(pro)
            conn.ack_num = sequence_number(pro) + 1

            conn.setDestinationAddress(address)
            conn.setSourceAddress(conn.socket.getsockname())
            break

    conn.timer.stop()
    return conn

def send(conn: Conn, data: bytes) -> int:
    INITIAL_SEQUENCE_NUMBER = conn.seq_num

    HOST, PORT = conn.source_address
    host, port = conn.destination_address

    cur = {}
    cur[conn.seq_num] = 0

    pieces = [data[i:min(len(data), i + DATA_SIZE)] for i
            in range(0, len(data), DATA_SIZE)]

    SEQ_NUMBER = conn.seq_num
    ACK_NUMBER = conn.ack_num
    times = 0
    conn.cack = 0
    conn.timer.mark()

    while cur[conn.seq_num] < len(pieces):
        try:
            _, pro, data = __read__(conn)
        except:
            timeout = conn.timer.running()
            if not conn.timer.running() or conn.timer.timeout():
                if timeout or conn.cack >= 4:
                    conn.cack = 1
                    conn.ws = max(1, conn.ws // 2)
                times += 1
                SEQ_NUMBER = conn.seq_num
                ACK_NUMBER = conn.ack_num

                for i in range(cur[conn.seq_num], min(cur[conn.seq_num] + conn.ws, len(pieces))):
                    cur[SEQ_NUMBER] = i
                    package = make_pro_header(PORT, port, SEQ_NUMBER, ACK_NUMBER + i - cur[conn.seq_num], conn.ws, data=pieces[i])

                    conn.socket.sendto(package, conn.destination_address)

                    SEQ_NUMBER += len(pieces[i])
                conn.timer.start()
                cur[SEQ_NUMBER] = min(cur[conn.seq_num] + conn.ws, len(pieces))

            if conn.timer.wait(180):
                conn.timer.stop()
                raise ConnException()
            continue

        if sequence_number(pro) < conn.ack_num or ack_number(pro) <= conn.seq_num \
                or not is_ack(pro):
            if ack_number(pro) < conn.seq_num: conn.cack += 1
            continue

        conn.timer.mark()
        conn.cack = 1
        conn.seq_num = ack_number(pro)
        conn.ack_num = sequence_number(pro) + 1

        if is_fin(pro):
            conn.timer.stop()
            package = make_pro_header(PORT, port, conn.seq_num, conn.ack_num, conn.ws, ACK=1, FIN=1)

            while True:
                try:
                    _, pro, data = __read__(conn)
                except:
                    if not conn.timer.running() or conn.timer.timeout():
                        conn.timer.start()
                        conn.socket.sendto(package, conn.destination_address)

                    if conn.timer.wait(30): break
                    continue

                if sequence_number(pro) != conn.ack_num or ack_number(pro) != conn.seq_num + 1 \
                        or not is_ack(pro):
                    continue

                conn.seq_num = ack_number(pro)
                conn.ack_num = sequence_number(pro) + 1
                conn.timer.stop()
                break
            conn.timer.stop()
            return conn.seq_num - INITIAL_SEQUENCE_NUMBER - 1

        if conn.seq_num == SEQ_NUMBER:
            if conn.cack < 3: conn.ws = min(2 * conn.ws, 128)
            conn.timer.stop(times <= 2)
            times = 0

    conn.timer.stop()
    package = make_pro_header(PORT, port, conn.seq_num, conn.ack_num, conn.ws, FIN=1)
    __wait_for_finack__(conn, package)

    return conn.seq_num - INITIAL_SEQUENCE_NUMBER - 1


def recv(conn: Conn, length: int) -> bytes:
    HOST, PORT = conn.source_address
    host, port = conn.destination_address

    BUFFER = b''
    times = 0

    conn.timer.mark()
    while len(BUFFER) < length:
        try: _, pro, data = __read__(conn)
        except:
            if not conn.timer.running() or conn.timer.timeout():
                conn.timer.start()
                times += 1

                package = make_pro_header(PORT, port, conn.seq_num, conn.ack_num, conn.ws, ACK=1)
                conn.socket.sendto(package, conn.destination_address)

            if conn.timer.wait(80):
                conn.timer.stop()
                break
            continue

        if sequence_number(pro) != conn.ack_num or ack_number(pro) != conn.seq_num + 1:
            continue

        if is_fin(pro):
            conn.timer.stop(times <= 2)
            conn.seq_num = ack_number(pro)
            conn.ack_num = sequence_number(pro) + 1
            package = make_pro_header(PORT, port, conn.seq_num, conn.ack_num, conn.ws, ACK=1, FIN=1)
            conn.timer.mark()
            while True:
                try:
                    _, pro, data = __read__(conn)
                except:
                    if not conn.timer.running() or conn.timer.timeout():
                        conn.timer.start()
                        conn.socket.sendto(package, conn.destination_address)

                    if conn.timer.wait(30): break
                    continue

                if sequence_number(pro) != conn.ack_num or ack_number(pro) != conn.seq_num + 1:
                    conn.socket.sendto(package, conn.destination_address)
                else:
                    conn.timer.stop()
                    break

            conn.timer.stop()
            return BUFFER
        else:
            conn.timer.mark()
            conn.timer.stop(times <= 2)

            if len(BUFFER) + len(data) >= length:
                data = data[:length - len(BUFFER)]

            BUFFER += data

            conn.seq_num = ack_number(pro)
            conn.ack_num += len(data)
            times = 0
    conn.timer.stop()
    if len(BUFFER) == length:
        package = make_pro_header(PORT, port, conn.seq_num, conn.ack_num, conn.ws, ACK=1,FIN=1)
        __wait_for_finack__(conn, package)

    return BUFFER


def close(conn: Conn):
    conn.socket.close()
    conn.socket = None


def __read__(conn : Conn):
    try:
        package, address = conn.socket.recvfrom(SEGMENT_SIZE)
    except BlockingIOError:
        return None

    ip, pro, data = get_segment(package)
    if is_corrupt(pro + data):
        return None

    #if address == conn.destination_address:
    #	conn.timer.mark()
    return (address, pro, data)

def __wait_for_finack__(conn : Conn, package):
    HOST, PORT = conn.source_address
    host, port = conn.destination_address
    if not package: package = make_pro_header(PORT, port, conn.seq_num, conn.ack_num, conn.ws, FIN=1, ACK=1)

    conn.timer.mark()
    while True:
        if not conn.timer.running() or conn.timer.timeout():
            conn.timer.start()
            conn.socket.sendto(package, conn.destination_address)

        if conn.timer.wait(20):
            conn.timer.stop()
            return

        try:
            _, pro, data = __read__(conn)
        except:
            continue

        if sequence_number(pro) != conn.ack_num or ack_number(pro) != conn.seq_num + 1\
                or not is_fin(pro) or not is_ack(pro):
            pass
        else:
            conn.timer.stop()
            conn.ack_num = sequence_number(pro) + 1
            conn.seq_num = ack_number(pro)
            break