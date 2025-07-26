from scapy.all import sniff, IP
from collections import defaultdict
import time

# Contador de pacotes por IP
contador_ips = defaultdict(int)
inicio = time.time()

def processar_pacote(pacote):
    if IP in pacote:
        ip_origem = pacote[IP].src
        contador_ips[ip_origem] += 1
        print(f"[PACOTE] De: {ip_origem} -> {pacote[IP].dst}")

        # Verifica se o IP excedeu 20 pacotes em menos de 5 segundos (simulação de DDoS)
        tempo_decorrido = time.time() - inicio
        if contador_ips[ip_origem] > 20 and tempo_decorrido < 5:
            print(f"[ALERTA] Possível ataque DDoS detectado de {ip_origem}!")

print("[INFO] Iniciando monitoramento com Scapy...")
sniff(prn=processar_pacote, filter="ip", store=0)
