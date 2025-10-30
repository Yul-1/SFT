#!/usr/bin/env python3
"""
test_concurrency.py

Test di concorrenza per secure_file_transfer_fixed.py.
Verifica che il server (v2.5 refactored) gestisca correttamente
connessioni multiple e trasferimenti simultanei senza corruzione
dati o race condition.
"""

import pytest
import threading
import socket
import time
import os
import hashlib
import sys
from pathlib import Path
from typing import List, Dict, Any

# --- Configurazione Path ---
# Aggiungiamo la root del progetto
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    from secure_file_transfer_fixed import SecureFileTransferNode, OUTPUT_DIR
    
except ImportError as e:
    print(f"Errore di import in test_concurrency: {e}")
    sys.exit(1)

# --- Costanti di Test ---
TEST_HOST = '127.0.0.1'
NUM_CONCURRENT_CLIENTS = 5 # Numero di client da eseguire in parallelo

# --- Fixtures ---

@pytest.fixture(scope="module")
def client_test_files(dummy_file_factory):
    """
    Crea i file sorgente necessari per i test di concorrenza.
    Usa la fixture 'dummy_file_factory' (definita in conftest.py)
    """
    files_to_create = [
        ("client_file_1.bin", 50),  # 50KB
        ("client_file_2.bin", 100), # 100KB
        ("client_file_3.bin", 20),  # 20KB
        ("client_file_4.bin", 75),
        ("client_file_5.bin", 10)
    ]
    
    # Crea solo i file necessari per NUM_CONCURRENT_CLIENTS
    created_files = {}
    for i in range(NUM_CONCURRENT_CLIENTS):
        if i < len(files_to_create):
            name, size = files_to_create[i]
            file_path = dummy_file_factory(name, size)
            
            # Calcola l'hash per la verifica
            content = file_path.read_bytes()
            file_hash = hashlib.sha256(content).hexdigest()
            created_files[str(file_path)] = file_hash
            
    return created_files

# --- Test Suite Concorrenza ---

# 1. Test di base della fixture
def test_server_fixture(persistent_server):
    """TEST 1: Verifica che la fixture 'persistent_server' sia attiva."""
    # 🟢 FIX: Usa la fixture 'persistent_server'
    assert persistent_server.running is True
    assert persistent_server.port != 0
    # Tenta una connessione socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((persistent_server.host, persistent_server.port))
        s.close()
    except Exception as e:
        pytest.fail(f"La fixture 'persistent_server' non risponde: {e}")

# 2. Test singolo client (verifica la baseline)
def test_single_client_transfer(persistent_server, client_test_files, server_output_dir):
    """TEST 2: Verifica un singolo trasferimento file E2E."""
    # 🟢 FIX: Usa la fixture 'persistent_server'
    host = persistent_server.host
    port = persistent_server.port
    
    # Prendi il primo file
    filepath, expected_hash = list(client_test_files.items())[0]
    
    client = SecureFileTransferNode(mode='client')
    try:
        client.connect_to_server(host, port)
        client.send_file(str(filepath))
    except Exception as e:
        pytest.fail(f"Test client singolo fallito: {e}")
    finally:
        client.shutdown()
        
    # Verifica il file
    received_file = server_output_dir / Path(filepath).name
    assert received_file.exists()
    assert hashlib.sha256(received_file.read_bytes()).hexdigest() == expected_hash

# 3. Test di concorrenza
def test_concurrent_client_transfers(persistent_server, client_test_files, server_output_dir):
    """
    TEST 3: Esegue N client in parallelo, ognuno inviando un file diverso.
    Verifica che TUTTI i file arrivino integri.
    """
    # 🟢 FIX: Usa la fixture 'persistent_server'
    host = persistent_server.host
    port = persistent_server.port
    
    # Lista per tenere traccia dei thread e dei risultati
    threads: List[threading.Thread] = []
    results: Dict[str, Any] = {} # Dict thread-safe
    
    # Funzione target per il thread
    def client_thread_task(filepath: str, thread_results: Dict):
        """
        Task eseguito da ogni thread client.
        Connette, invia 1 file, disconnette.
        """
        client_node = SecureFileTransferNode(mode='client')
        thread_id = threading.current_thread().name
        try:
            client_node.connect_to_server(host, port)
            client_node.send_file(str(filepath))
            thread_results[thread_id] = "SUCCESS"
        except Exception as e:
            thread_results[thread_id] = f"FAILED: {e}"
        finally:
            client_node.shutdown()

    # Avvia i thread
    print(f"\n[Test Concorrenza] Avvio di {NUM_CONCURRENT_CLIENTS} client...")
    
    # Assicurati che il numero di file corrisponda
    file_items = list(client_test_files.items())
    assert len(file_items) >= NUM_CONCURRENT_CLIENTS

    for i in range(NUM_CONCURRENT_CLIENTS):
        filepath, _ = file_items[i]
        t = threading.Thread(
            target=client_thread_task, 
            args=(filepath, results),
            name=f"ClientTask-{i+1}"
        )
        t.start()
        threads.append(t)
        
    # Attendi il completamento
    for t in threads:
        t.join(timeout=30.0) # Timeout 30 secondi

    print(f"[Test Concorrenza] Thread completati. Risultati: {results}")

    # 1. Verifica che tutti i thread abbiano avuto successo
    assert len(results) == NUM_CONCURRENT_CLIENTS
    for thread_id, status in results.items():
        assert status == "SUCCESS", f"Thread {thread_id} fallito: {status}"

    # 2. Verifica che tutti i file siano stati ricevuti e siano corretti
    print(f"[Test Concorrenza] Verifica file in {OUTPUT_DIR}...")
    
    assert len(list(server_output_dir.glob("*.bin"))) == NUM_CONCURRENT_CLIENTS
    
    for filepath_str, expected_hash in client_test_files.items():
        filename = Path(filepath_str).name
        received_file = server_output_dir / filename
        
        print(f"Verifica: {filename}...")
        
        assert received_file.exists(), f"File {filename} non trovato"
        
        # Calcola l'hash del file ricevuto
        received_hash = hashlib.sha256(received_file.read_bytes()).hexdigest()
        assert received_hash == expected_hash, f"Hash mismatch per {filename}"
        
    print("[Test Concorrenza] Tutti i file sono stati verificati.")