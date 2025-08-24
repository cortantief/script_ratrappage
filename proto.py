import struct, os
from enum import Enum

MAGIC = b"SH"
VERSION = 1
MIN_BASE = "!2sB B"
NF_HDR_FMT = f"{MIN_BASE} H H H" # NEW_FILE_FORMAT
EOF_HDR_FMT = f"{MIN_BASE} H H" # EOF_FILE_FORMAT
SESS_HDR_FMT = f"{MIN_BASE}" # SESSION_FORMAT
SFD_HDR_FMT = f"{MIN_BASE} H H H H" # SEND_FILE_FORMAT

class MiniProtoFlag(Enum):
    NEW_SESSION = 0
    CLOSE_SESSION = 1
    NEW_FILE = 2
    SEND_DATA = 3
    EOF = 4

class MiniProto:
    def __init__(self, mtu=1500):
        ip_header = 20
        icmp_header = 8
        self.packet_buffer = mtu - (ip_header + icmp_header)
        
    def build_nw_file(self, sess_id: int, file_id: int, filename: str) -> bytes:
        msg_size = len(filename)
        MAX_PAQUET_SIZE = self.packet_buffer - struct.calcsize(NF_HDR_FMT)
        if MAX_PAQUET_SIZE - msg_size <= 0:
            raise ValueError("message too long")
        return struct.pack(NF_HDR_FMT, MAGIC, VERSION, MiniProtoFlag.NEW_FILE.value, sess_id, file_id, msg_size) + filename
    
    def build_nw_session(self, sess_id: int) -> bytes:
        return struct.pack(SESS_HDR_FMT, MAGIC, VERSION, MiniProtoFlag.NEW_SESSION.value) + (sess_id).to_bytes(2, byteorder='big')

    def build_close_session(self, sess_id: int) -> bytes:
        return struct.pack(SESS_HDR_FMT, MAGIC, VERSION, MiniProtoFlag.CLOSE_SESSION.value) + (sess_id).to_bytes(2, byteorder='big')

    def build_eof(self, sess_id: int, file_id: int) -> bytes:
        return struct.pack(EOF_HDR_FMT, MAGIC, VERSION, MiniProtoFlag.EOF.value, sess_id, file_id)
    
    def build_sfd_file(self,  sess_id: int, file_id: int, fpath: str):
        MAX_PAQUET_SIZE = self.packet_buffer - struct.calcsize(SFD_HDR_FMT)
        with open(fpath, "rb") as f:
            seq = 0
            while data := f.read(MAX_PAQUET_SIZE):
                seq += 1
                yield struct.pack(SFD_HDR_FMT, MAGIC, VERSION, MiniProtoFlag.SEND_DATA.value, sess_id, file_id, seq, len(data)) + data

