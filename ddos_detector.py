from scapy.all import sniff, IP
from collections import defaultdict, deque
import os
import time
import json
import threading

# CONFIGURAÇÕES
MAX_PACKETS = 100
TIME_WINDOW = 10  # segundos
ip_traffic = defaultdict(lambda: deque())

# ==========================
# ETAPA 1 - DETECÇÃO POR SCAPY
# ==========================
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        now = time.time()
        ip_traffic[ip_src].append(now)

        # Limpa timestamps antigos
        while ip_traffic[ip_src] and now - ip_traffic[ip_src][0] > TIME_WINDOW:
            ip_traffic[ip_src].popleft()

        if len(ip_traffic[ip_src]) > MAX_PACKETS:
            print(f"[ALERTA] DDoS detectado de {ip_src} via Scapy")
            block_ip_windows(ip_src)

# ==========================
# ETAPA 2 - BLOQUEIO NO WINDOWS
# ==========================
def block_ip_windows(ip):
    try:
        print(f"[FIREWALL] Bloqueando IP: {ip}")
        os.system(f'netsh advfirewall firewall add rule name="Bloqueio {ip}" dir=in interface=any action=block remoteip={ip}')
    except Exception as e:
        print(f"[ERRO] ao bloquear {ip}: {e}")

# ==========================
# ETAPA 3 - RELATÓRIO JSON
# ==========================
def gerar_relatorio():
    print("[INFO] Gerando relatório JSON...")
    relatorio = {ip: len(reqs) for ip, reqs in ip_traffic.items()}
    with open("relatorio_ddos.json", "w") as f:
        json.dump(relatorio, f, indent=4)

# ==========================
# MAIN
# ==========================
if __name__ == "__main__":
    try:
        print("[INFO] Iniciando monitoramento com Scapy...")
        sniff_thread = threading.Thread(target=lambda: sniff(filter="ip", prn=packet_callback, store=0))
        sniff_thread.daemon = True
        sniff_thread.start()

        # Mantenha o programa rodando
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        gerar_relatorio()
        print("[INFO] Execução encerrada.")
