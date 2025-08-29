from scapy.all import sniff, IP, ICMP, Raw, get_if_list
from proto import *
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

import argparse

console = Console()

# Palette de couleurs par type de trame pour l’affichage

FLAG_STYLES = {
    MiniProtoFlag.NEW_SESSION:   ("NEW_SESSION", "blue"),
    MiniProtoFlag.CLOSE_SESSION: ("CLOSE_SESSION", "red"),
    MiniProtoFlag.NEW_FILE:      ("NEW_FILE", "yellow"),
    MiniProtoFlag.SEND_DATA:     ("SEND_DATA", "green"),
    MiniProtoFlag.EOF:           ("EOF", "magenta"),
}

def _preview_hex(b: bytes, max_bytes: int = 32) -> str:
    """Retourne un aperçu hex tronqué pour log."""
    if not b:
        return "—"
    h = b[:max_bytes].hex()
    return h if len(b) <= max_bytes else h + " …"


def parse_proto(payload: bytes):
    """
    Décode un payload MiniProto et renvoie (flag_enum, info_dict).
    Effectue des contrôles de longueur à chaque étape.
    """

    # Check si la taille du payload correspond au plus petit
    # dénominateur commun dans le flag. Si trop petit pour un header
    # ce n'est pas un payload de MiniProto
    # En-tête minimal : MAGIC (2) | VERSION (1) | FLAG (1)
    if len(payload) < struct.calcsize(MIN_BASE):
        raise ValueError("payload too short")

    magic, ver, flag = struct.unpack_from(MIN_BASE, payload, 0)
    if magic != MAGIC:
        raise ValueError(f"bad magic {magic!r}")
    if ver != VERSION:
        raise ValueError(f"unsupported version {ver}")

    try:
        flag_enum = MiniProtoFlag(flag)
    except ValueError:
        raise ValueError(f"unknown flag {flag}")

    # NEW_SESSION / CLOSE_SESSION : header commun + sess_id (2 octets après)
    if flag_enum in (MiniProtoFlag.NEW_SESSION, MiniProtoFlag.CLOSE_SESSION):
        need = struct.calcsize(SESS_HDR_FMT) + 2
        if len(payload) < need:
            raise ValueError("session frame too short")
        sess_id = int.from_bytes(payload[4:6], "big")
        return flag_enum, {"sess_id": sess_id}
    
    # NEW_FILE : header + champs sess_id/file_id/name_len + bytes du filename
    elif flag_enum == MiniProtoFlag.NEW_FILE:
        need = struct.calcsize(NF_HDR_FMT)
        if len(payload) < need:
            raise ValueError("new_file header too short")
        _, _, _, sess_id, file_id, name_len = struct.unpack_from(NF_HDR_FMT, payload, 0)
        total = need + name_len
        if len(payload) < total:
            raise ValueError("filename truncated")
        filename = payload[need:total]
        return flag_enum, {
            "sess_id": sess_id,
            "file_id": file_id,
            "name_len": name_len,
            "filename": filename,
        }
    
    # SEND_DATA : header + data (len=data_len)
    elif flag_enum == MiniProtoFlag.SEND_DATA:
        need = struct.calcsize(SFD_HDR_FMT)
        if len(payload) < need:
            raise ValueError("send_data header too short")
        _, _, _, sess_id, file_id, seq, data_len = struct.unpack_from(SFD_HDR_FMT, payload, 0)
        total = need + data_len
        if len(payload) < total:
            raise ValueError("data chunk truncated")
        data = payload[need:total]
        return flag_enum, {
            "sess_id": sess_id,
            "file_id": file_id,
            "seq": seq,
            "data_len": data_len,
            "data": data,
        }
    
    # EOF : fin de fichier 
    elif flag_enum == MiniProtoFlag.EOF:
        need = struct.calcsize(EOF_HDR_FMT)
        if len(payload) < need:
            raise ValueError("eof header too short")
        _, _, _, sess_id, file_id = struct.unpack_from(EOF_HDR_FMT, payload, 0)
        return flag_enum, {"sess_id": sess_id, "file_id": file_id}

    else:
        raise ValueError(f"unhandled flag {flag_enum}")


class SessionStore:
    """
    Stocke l'état par session et recompose les fichiers.
    Structure: sessions[sess_id][file_id] = (filename, [(seq, data), ...])
    """
    def __init__(self):
        self.sessions = {}
    
    def new_session(self, sess_id: int):
        self.sessions[sess_id] = {}

    def new_file(self, sess_id: int, file_id: int, filename: str):
        d = self.sessions.get(sess_id)
        d[file_id] = (filename, [])
    
    def eof(self, sess_id: int, file_id: int):
        """Trie par seq et écrit le fichier quand EOF est reçu."""
        sess = self.sessions.get(sess_id)
        if not sess:
            return
        obj = sess.get(file_id)
        if not obj:
            return
        filename, data = obj
        data = sorted(data)
        with open(filename, "wb") as f:
            for i in data:
                f.write(i[1])
        sess[file_id] = None
    
    def on_data(self, sess_id: int, file_id: int, seq: int, data: bytes ):
        """Accumule les blocs (seq, data) en RAM ; l'écriture se fait à EOF."""
        sess = self.sessions.get(sess_id)
        if not sess:
            return
        obj = sess.get(file_id)
        if not obj:
            return
        obj[1].append((seq, data))
    
    def close_session(self, sess_id: int):
        self.sessions[sess_id] = None

def icmp_responder(iface: str = None):
    """
    Boucle principale de capture et dispatch.
    Filtre ICMP Echo Request
    """
    session_store = SessionStore()

    # Handlers qui manipulent le SessionStore en fonction des flag
    def on_new_session(info):   session_store.new_session(info['sess_id'])
    def on_close_session(info): session_store.close_session(info["sess_id"])
    def on_new_file(info):      session_store.new_file(info['sess_id'], info['file_id'], info['filename'])
    def on_send_data(info):     session_store.on_data(info['sess_id'], info['file_id'], info['seq'], info["data"])
    def on_eof(info):           session_store.eof(info["sess_id"], info["file_id"])

    HANDLERS = {
        MiniProtoFlag.NEW_SESSION:   on_new_session,
        MiniProtoFlag.CLOSE_SESSION: on_close_session,
        MiniProtoFlag.NEW_FILE:      on_new_file,
        MiniProtoFlag.SEND_DATA:     on_send_data,
        MiniProtoFlag.EOF:           on_eof,
    }
    def handle(pkt):
        # Garde uniquement IP/ICMP Echo Request
        if IP in pkt and ICMP in pkt and pkt[ICMP].type == 8:
            src, dst = pkt[IP].src, pkt[IP].dst
            payload = pkt[Raw].load if Raw in pkt else b""

            console.print(
                f":satellite: [bold cyan]ICMP Echo Request[/] "
                f"[white]{src}[/] → [white]{dst}[/]  [dim]payload={len(payload)}B[/]"
            )

            try:
                flag, info = parse_proto(payload)

                label, color = FLAG_STYLES.get(flag, (flag.name, "white"))
                table = Table(box=box.SIMPLE_HEAVY, show_header=False, expand=True, padding=(0,1))
                table.add_row("Flag", f"[bold]{label}[/]")
                table.add_row("Source", src)
                table.add_row("Destination", dst)

                # Per-flag fields
                if "sess_id" in info:
                    table.add_row("Session ID", str(info["sess_id"]))
                if "file_id" in info:
                    table.add_row("File ID", str(info["file_id"]))
                if "name_len" in info:
                    table.add_row("Name Len", str(info["name_len"]))
                if "filename" in info:
                    try:
                        table.add_row("Filename", info["filename"].decode(errors="replace"))
                    except Exception:
                        table.add_row("Filename", repr(info["filename"]))
                if "seq" in info:
                    table.add_row("Seq", str(info["seq"]))
                if "data_len" in info:
                    table.add_row("Data Len", str(info["data_len"]))
                if "data" in info:
                    table.add_row("Data Preview", _preview_hex(info["data"]))

                table.add_row("Payload (hex)", _preview_hex(payload))

                console.print(Panel(table, title=f"[bold]{label}[/]", border_style=color))

                # Dispatch vers le handler de ce flag
                # Par défaut retourne une fonction qui ne fait rien
                # évitant ainsi les crashs
                HANDLERS.get(flag, lambda _i: None)(info)
            
            # Catch erreur
            except Exception as e:

                err = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False, expand=True)
                err.add_row("Reason", f"[red]{e}[/]")
                err.add_row("Payload (hex)", _preview_hex(payload))
                console.print(Panel(err, title="[bold red]MiniProto parse error[/]", border_style="red"))


    # Filtre uniquement Echo Request dans le sniff
    lfilter = lambda p: IP in p and ICMP in p and getattr(p[ICMP], "type", None) == 8
    sniff(prn=handle, lfilter=lfilter, store=0, iface=iface)


parser = argparse.ArgumentParser()
parser.add_argument("--interface", "-i", choices=get_if_list(), required=True)

if __name__ == "__main__":
    args = parser.parse_args()
    icmp_responder(args.interface)
    