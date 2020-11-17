U = (1<<16) - 1

def sum_hex(arr):
    s = 0
    for i in range(0, len(arr), 2):
        s += int.from_bytes(arr[i:min(i + 2, len(arr))], byteorder = 'big', signed = False)
    return s & U

def make_ip_header(source_ip, destination_ip):
    ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum   xff en protocol
    source_ip = [int(i) for i in source_ip.split('.')]
    destination_ip = [int(i) for i in destination_ip.split('.')]
    ip_header += bytes(source_ip)  # Source Address
    ip_header += bytes(destination_ip)  # Destination Address
    return ip_header

def get_address(ip_header):
    return (str(ip_header[12:16]), str(ip_header[16:]))

def make_pro_header(sport, dport, seqnumber, acknumber, window_size, ACK = 0, SYN = 0, FIN = 0, data = b''):
    tcp_header = sport.to_bytes(2, byteorder='big', signed=False) # Source Port
    tcp_header += dport.to_bytes(2, byteorder='big', signed=False) # Destination Port
    tcp_header += seqnumber.to_bytes(4, byteorder = 'big', signed = False)  # Sequence Number
    tcp_header += acknumber.to_bytes(4, byteorder = 'big', signed = False)  # Acknowledgement Number
    tcp_header += ((ACK<<4) + (SYN << 1) + (FIN)).to_bytes(2, byteorder='big', signed=False) # Flags
    tcp_header += window_size.to_bytes(2, byteorder='big', signed=False) # Window Size
    tcp_header += b'\x00\x00\x00\x00'  # Checksum | Urgent Pointer

    checksum = sum_hex(data) + sum_hex(tcp_header)
    checksum = U - (checksum & U)
    checksum = checksum.to_bytes(2, byteorder='big', signed=False)

    tcp_header = tcp_header[:16] + checksum + tcp_header[18:]

    return tcp_header + data

def make_packet(ip_header, pro_header):
    return ip_header + pro_header

def is_corrupt(segment):
    return (sum_hex(segment) & U) != U

def get_segment(packet):
    return (packet[:20], packet[20:40], packet[40:])

def sequence_number(segment):
    return int.from_bytes(segment[4:8], byteorder = 'big', signed = False)

def ack_number(segment):
    return int.from_bytes(segment[8:12], byteorder = 'big', signed = False)

def get_window_size(segment):
    return int.from_bytes(segment[14:16], byteorder = 'big', signed = False)

def is_ack(segment):
    return ((segment[13] >> 4) & 1) == 1

def is_syn(segment):
    return ((segment[13] >> 1) & 1) == 1

def is_fin(segment):
    return ((segment[13]) & 1) == 1

