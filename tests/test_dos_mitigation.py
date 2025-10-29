import pytest
import threading
import socket
import time
import logging
import os
from pathlib import Path
# 🟢 CORREZIONE: Assicurati che il file del server sia trovato
# Aggiungiamo la root del progetto al path per gli import
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from secure_file_transfer_fixed import SecureFileTransferNode, DEFAULT_PORT

# --- Fixture per il Server e il File di Test ---

@pytest.fixture(scope="function")
def running_server():
    """Avvia il server in un thread separato per ogni test."""
    
    # 🟢 MODIFICA: Chiedi al SO una porta libera (porta 0)
    server = SecureFileTransferNode(mode='server', host='127.0.0.1', port=0)
    
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # Dai al server il tempo di avviarsi
    time.sleep(0.5) 
    
    # 🟢 MODIFICA: Assicurati che il server sia partito e abbia una porta
    if not server.running or server.port == 0:
        pytest.fail("Il server non è riuscito ad avviarsi o ottenere una porta.")

    yield server
    
    # Teardown
    server.shutdown()
    server_thread.join(timeout=1.0)
    # Pulisci i file ricevuti per evitare interferenze
    for f in Path("ricevuti").glob("*"):
        try:
            os.remove(f)
        except:
            pass

@pytest.fixture(scope="module")
def test_file(tmp_path_factory):
    """Crea un file fittizio per il trasferimento (basta uno per modulo)."""
    file_path = tmp_path_factory.mktemp("test_files") / "sample_file.txt"
    with open(file_path, "w") as f:
        f.write("Questo è un test di trasferimento file.")
    return file_path

# --- Funzione Helper per l'Attaccante ---
# (Questa funzione non cambia, ma la includo per completezza)
def attacker_connect(host, port):
    """
    Simula un singolo tentativo di connessione che non fa nulla.
    Il server lo chiuderà o per rate-limit o per handshake fallito.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((host, port))
            # Attendiamo passivamente che il server chiuda la connessione
            s.recv(1024) 
    except Exception:
        # Ci aspettiamo fallimenti (Timeout, ConnectionResetError, ecc.)
        pass 

# --- Test Case ---

def test_connection_limiter_blocks_flood(running_server, caplog):
    """
    Testa che il ConnectionLimiter blocchi connessioni 
    multiple dallo stesso IP.
    """
    caplog.set_level(logging.INFO)
    
    attacker_host = '127.0.0.1'
    # 🟢 MODIFICA: Usa la porta dinamica assegnata dalla fixture
    attacker_port = running_server.port
    
    num_attempts = 15
    limit = 10 # Come da implementazione
    
    threads = []
    print(f"\n[TEST] Avvio del flood di connessioni verso {attacker_host}:{attacker_port}...")
    
    for i in range(num_attempts):
        t = threading.Thread(target=attacker_connect, args=(attacker_host, attacker_port))
        t.start()
        threads.append(t)
        time.sleep(0.05) 

    for t in threads:
        t.join(timeout=3.0)
        
    print("[TEST] Flood completato. Analisi dei log...")

    log_messages = [record.message for record in caplog.records]
    
    incoming_logs = [
        m for m in log_messages 
        if f"Incoming connection attempt from {attacker_host}" in m
    ]
    
    rate_limit_logs = [
        m for m in log_messages 
        if f"Connection rate limit (pre-handshake) exceeded for {attacker_host}" in m
    ]
    
    print(f"[RISULTATO] Log 'Incoming' catturati: {len(incoming_logs)}")
    print(f"[RISULTATO] Log 'Rate Limit' catturati: {len(rate_limit_logs)}")

    # Asserzione 1: Il server deve aver registrato TUTTI i tentativi
    assert len(incoming_logs) == num_attempts
    
    # Asserzione 2: Il server deve aver RIFIUTATO (num_attempts - limit) connessioni
    assert len(rate_limit_logs) == num_attempts - limit

def test_legitimate_client_works(running_server, test_file):
    """
    Testa che un client legittimo possa connettersi 
    e trasferire un file.
    Grazie a scope="function", questo server è "pulito".
    """
    client = SecureFileTransferNode(mode='client')
    
    # 🟢 MODIFICA: Usa la porta dinamica assegnata dalla fixture
    connect_port = running_server.port
    print(f"\n[TEST] Client legittimo si connette a 127.0.0.1:{connect_port}...")

    try:
        client.connect_to_server('127.0.0.1', connect_port)
        client.send_file(str(test_file))
    except Exception as e:
        pytest.fail(f"Il client legittimo non è riuscito a connettersi o trasferire: {e}")
    finally:
        # Assicurati che il client si chiuda anche in caso di fallimento
        client.shutdown()

    # Verifica che il file sia stato ricevuto correttamente
    received_path = Path("ricevuti") / test_file.name
    assert received_path.exists()
    assert received_path.stat().st_size == test_file.stat().st_size
    # Pulisci (lo fa anche la fixture, ma è buona norma)
    os.remove(received_path)