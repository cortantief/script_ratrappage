from scapy.all import IP, ICMP, send, conf
import argparse, os, random
from ipaddress import ip_address
from proto import MiniProto


conf.verb = 0   # turn off global verbosity


def valid_file(path: str) -> str:
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"File '{path}' does not exist.")
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"'{path}' is not a file.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"File '{path}' is not readable.")

    return path

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--destination", type=ip_address,required=True)
parser.add_argument("-f", "--files", nargs='+',type=valid_file,required=True)

args = parser.parse_args()

target = args.destination
proto = MiniProto()
sess_id = random.randint(1, 0xffff)
PACKET_BASE = IP(dst=target.__str__())/ICMP()

send(PACKET_BASE/(proto.build_nw_session(sess_id)))

for file in args.files:
    file_id = random.randint(1, 0xffff)
    filename_str = os.path.basename(file)
   
    packet = PACKET_BASE/(proto.build_nw_file(sess_id, file_id, os.path.basename(file).encode()))
    send(packet)
    for data in proto.build_sfd_file(sess_id, file_id, file):
        packet  = PACKET_BASE/data
        send(packet)
    packet = PACKET_BASE/proto.build_eof(sess_id, file_id)
    send(packet)

send(PACKET_BASE/(proto.build_close_session(sess_id)))