# POC d’exfiltration via ICMP (MiniProto)

## Objectif
Démontrer qu'il est possible de transporter un fichier dans le **payload d’ICMP Echo Request**. 

## Prérequis
- **Système recommandé :** Linux.
- **Python :** 3.9+ et dépendances du projet (voir **requirements.txt**).
- **Droits :** privilèges réseau suffisants (root ou capacité équivalente) pour émettre/sniffer ICMP.
- **Réseau :** ICMP autorisé entre le client « victime » et le serveur d’exfiltration.

## Structure du projet
- `proto.py` - définition de **MiniProto**.
- `main.py` - **client** : envoie une session d’exfiltration ICMP avec MiniProto.
- `server.py` - **serveur** : sniffe ICMP, parse MiniProto, réassemble les blocs et écrit le fichier.

## Étapes préliminaires

Le POC est testé sur une machine Linux.

```sh
sudo apt install python3 python3-venv
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "$(which python3)"
echo 1 | sudo tee /proc/sys/net/ipv4/icmp_echo_ignore_all
python3 -m venv env
source ./env/bin/activate
pip install -r requirements.txt
```

## Crédits
- **Scapy** pour la manipulation d’IP/ICMP.
- **Rich** pour l’affichage console.
