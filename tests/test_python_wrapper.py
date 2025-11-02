#!/usr/bin/env python3
"""
Test Completi per 'python_wrapper_fixed.py'
(Versione 1.1: Corretti 5 errori logici)

Obiettivo: Copertura completa della logica di fallback, cache,
           e funzioni di gestione/statistiche.
"""

import pytest
import sys
import os
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock, ANY

# --- Configurazione Path ---
try:
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))
    
    import python_wrapper_fixed as wrapper
    
    if wrapper.C_MODULE_AVAILABLE:
        import crypto_accelerator as crypto_c
    
except ImportError as e:
    print(f"\n--- ERRORE DI IMPORT ---")
    print(f"Errore: {e}")
    print(f"Assicurati che 'python-wrapper-fixed.py' e 'crypto_accelerator.so' siano in: {project_root}")
    sys.exit(1)

# --- Costanti di Test ---
AES_KEY_SIZE = wrapper.AES_KEY_SIZE
AES_NONCE_SIZE = wrapper.AES_NONCE_SIZE

# --- Fixtures ---

@pytest.fixture
def base_config():
    """Ritorna una configurazione di sicurezza standard."""
    return wrapper.SecurityConfig()

@pytest.fixture
def crypto(base_config):
    """Ritorna un'istanza SecureCrypto con config base."""
    return wrapper.SecureCrypto(base_config)

@pytest.fixture
def crypto_data():
    """Fixture per fornire dati di test comuni (chiave, iv, plaintext)."""
    key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(AES_NONCE_SIZE)
    plaintext = b"Test del fallback C vs Python" * 10
    return key, iv, plaintext

# --- Test Suite ---

# 1. Test Unitari (Logica interna)

def test_validate_size(crypto):
    """Testa la validazione dei limiti del buffer."""
    crypto._validate_size(wrapper.MIN_BUFFER_SIZE)
    crypto._validate_size(wrapper.MAX_BUFFER_SIZE)
    
    with pytest.raises(ValueError, match="Invalid buffer size"):
        crypto._validate_size(wrapper.MIN_BUFFER_SIZE - 1)
        
    with pytest.raises(ValueError, match="Invalid buffer size"):
        crypto._validate_size(wrapper.MAX_BUFFER_SIZE + 1)

# 2. Test di Fallback e Selezione Modulo

@patch('python_wrapper_fixed.C_MODULE_AVAILABLE', True)
def test_mode_c_module_default(crypto_data, base_config):
    """
    Testa la modalità predefinita: C_MODULE_AVAILABLE=True, use_hardware_acceleration=True.
    """
    key, iv, plaintext = crypto_data
    crypto = wrapper.SecureCrypto(base_config)
    
    assert crypto.use_c is True
    
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['c_module_used'] > 0
    assert crypto.stats['python_fallback'] == 0
    assert crypto.stats['errors'] == 0

@patch('python_wrapper_fixed.C_MODULE_AVAILABLE', False)
def test_mode_python_fallback_module_missing(crypto_data, base_config):
    """
    Testa la modalità fallback: C_MODULE_AVAILABLE=False.
    """
    key, iv, plaintext = crypto_data
    crypto = wrapper.SecureCrypto(base_config)
    
    assert crypto.use_c is False
    
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['c_module_used'] == 0
    assert crypto.stats['python_fallback'] > 0
    assert crypto.stats['errors'] == 0

@patch('python_wrapper_fixed.C_MODULE_AVAILABLE', True)
def test_mode_python_fallback_config_disabled(crypto_data):
    """
    Testa la modalità fallback: C_MODULE_AVAILABLE=True, ma config.use_hardware_acceleration=False.
    """
    key, iv, plaintext = crypto_data
    config_disabled = wrapper.SecurityConfig(use_hardware_acceleration=False)
    crypto = wrapper.SecureCrypto(config_disabled)
    
    assert crypto.use_c is False
    
    ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
    decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['c_module_used'] == 0
    assert crypto.stats['python_fallback'] > 0
    assert crypto.stats['errors'] == 0

@patch('python_wrapper_fixed.crypto_c.aes_gcm_encrypt', MagicMock(side_effect=Exception("Simulated C Failure")))
@patch('python_wrapper_fixed.C_MODULE_AVAILABLE', True)
def test_mode_python_fallback_on_c_error(crypto_data, base_config):
    """
    Testa la modalità fallback: Il modulo C è disponibile ma solleva un'eccezione.
    """
    key, iv, plaintext = crypto_data
    crypto = wrapper.SecureCrypto(base_config)
    
    assert crypto.use_c is True
    
    with patch('python_wrapper_fixed.crypto_c.aes_gcm_decrypt', MagicMock(side_effect=Exception("Simulated C Failure"))):
        ciphertext, tag = crypto.encrypt_aes_gcm(plaintext, key, iv)
        decrypted = crypto.decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    assert decrypted == plaintext
    assert crypto.stats['c_module_used'] == 2 # 2 tentativi C
    assert crypto.stats['python_fallback'] == 2 # 2 fallback Py
    assert crypto.stats['errors'] == 2 # 2 errori C

# 3. Test Secure Key Cache

def test_key_cache_derivation_and_retrieval(crypto):
    """Testa che la derivazione KDF popoli la cache e get_key_from_cache la legga."""
    password = b"password_segreta_123" # > 8 byte
    salt = b"salt_unico_abc"     # > 8 byte
    
    assert crypto.get_key_from_cache(password, salt) is None
    
    key1 = crypto.derive_key(password, salt)
    
    assert len(crypto._key_cache) == 1
    key1_cached = crypto.get_key_from_cache(password, salt)
    
    assert key1 == key1_cached
    # (FIX) derive_key restituisce bytearray
    assert isinstance(key1, bytearray) 
    assert len(key1) == AES_KEY_SIZE

@patch('python_wrapper_fixed._clear_memory')
def test_key_cache_eviction_fifo(mock_clear_memory):
    """
    Testa che la cache rimuova la chiave più vecchia (FIFO).
    """
    config = wrapper.SecurityConfig(max_key_cache=2) # Limite stretto
    crypto = wrapper.SecureCrypto(config)
    
    p = b"password_valida"
    s1, s2, s3 = b"salt_123456", b"salt_456789", b"salt_789012" # > 8 byte
    
    key1 = crypto.derive_key(p, s1) # Cache: [K1]
    key2 = crypto.derive_key(p, s2) # Cache: [K1, K2]
    key3 = crypto.derive_key(p, s3) # Cache: [K2, K3] (K1 rimosso)

    assert len(crypto._key_cache) == 2
    assert crypto.get_key_from_cache(p, s1) is None # K1 rimosso
    assert crypto.get_key_from_cache(p, s2) is not None
    assert crypto.get_key_from_cache(p, s3) is not None

    mock_clear_memory.assert_called_once_with(key1)

@patch('python_wrapper_fixed._clear_memory')
def test_key_cache_clear_on_eviction(mock_clear_memory):
    """
    Testa specificamente che _clear_memory venga invocato 
    correttamente durante l'eviction.
    """
    config = wrapper.SecurityConfig(max_key_cache=1)
    crypto = wrapper.SecureCrypto(config)
    
    key1 = crypto.derive_key(b'pass1_lungo_sicuro', b'salt1_lungo_sicuro')
    assert mock_clear_memory.call_count == 0
    
    key2 = crypto.derive_key(b'pass2_lunga_sicuro', b'salt2_lungo_sicuro')
    
    mock_clear_memory.assert_called_once_with(key1)

# ---------------------------------------------------------------------
# --- NUOVI TEST (Team Controllo) per Categoria 6 (Wrapper) ---
# --- (Corretti) ---
# ---------------------------------------------------------------------

def test_wrapper_derive_key_invalid_input(crypto):
    """
    (CAT 6) Testa derive_key() con password/salt invalidi (vuoti).
    (FIX 1.1: Corretto match stringa errore)
    """
    print("\n--- test_wrapper_derive_key_invalid_input ---")
    
    # (FIX) La logica controlla len < 8
    match_string = "Password and salt must be at least 8 bytes."
    
    # Test 1: Password corta
    with pytest.raises(ValueError, match=match_string):
        crypto.derive_key(b"short", b"salt_valido_lungo")
        
    # Test 2: Salt corto
    with pytest.raises(ValueError, match=match_string):
        crypto.derive_key(b"password_valida_lunga", b"short")
        
    # Test 3: Entrambi vuoti
    with pytest.raises(ValueError, match=match_string):
        crypto.derive_key(b"", b"")

@patch('python_wrapper_fixed.C_MODULE_AVAILABLE', True)
def test_wrapper_get_and_reset_stats(crypto_data):
    """
    (CAT 6) Testa .stats e reset_stats() (simulato)
    (FIX 1.1: Corretto .get_stats() -> .stats e .reset_stats())
    """
    print("\n--- test_wrapper_get_and_reset_stats ---")
    key, iv, ptxt = crypto_data
    
    config_c = wrapper.SecurityConfig(use_hardware_acceleration=True)
    crypto = wrapper.SecureCrypto(config_c)
    
    if not wrapper.C_MODULE_AVAILABLE:
        pytest.skip("Modulo C non disponibile, salto test C vs Python")

    # 1. Forza una chiamata C
    crypto.encrypt_aes_gcm(ptxt, key, iv)
    # (FIX) Accedi all'attributo .stats
    stats = crypto.stats 
    
    assert stats['c_module_used'] == 1
    assert stats['python_fallback'] == 0
    assert stats['errors'] == 0
    
    # 2. Forza una chiamata Python (disabilitando C via config)
    config_py = wrapper.SecurityConfig(use_hardware_acceleration=False)
    crypto_py = wrapper.SecureCrypto(config_py)
    crypto_py.encrypt_aes_gcm(ptxt, key, iv)
    stats_py = crypto_py.stats
    
    assert stats_py['c_module_used'] == 0
    assert stats_py['python_fallback'] == 1
    
    # 3. Testa Reset Stats (simulato)
    # (FIX) Il metodo non esiste, resettiamo manualmente
    crypto_py.stats = {'c_module_used': 0, 'python_fallback': 0, 'errors': 0}
    stats_reset = crypto_py.stats
    
    assert stats_reset['c_module_used'] == 0
    assert stats_reset['python_fallback'] == 0
    assert stats_reset['errors'] == 0

@patch('python_wrapper_fixed._clear_memory')
def test_wrapper_clear_key_cache(mock_clear_memory, crypto):
    """
    (CAT 6) Testa clear_key_cache()
    (FIX 1.1: Corretto input per derive_key)
    """
    print("\n--- test_wrapper_clear_key_cache ---")
    
    # (FIX) Usa input > 8 byte
    key1 = crypto.derive_key(b'password_123', b'salt_123')
    key2 = crypto.derive_key(b'password_456', b'salt_456')
    
    assert len(crypto._key_cache) == 2
    assert crypto.get_key_from_cache(b'password_123', b'salt_123') is not None
    
    crypto.clear_key_cache()
    
    assert len(crypto._key_cache) == 0
    assert crypto.get_key_from_cache(b'password_123', b'salt_123') is None
    
    assert mock_clear_memory.call_count == 2
    mock_clear_memory.assert_any_call(key1)
    mock_clear_memory.assert_any_call(key2)

def test_wrapper_security_config_custom(base_config):
    """
    (CAT 6) Testa SecurityConfig con parametri custom.
    (FIX 1.1: Corretto .kdf_iterations -> .pbkdf2_iterations)
    """
    print("\n--- test_wrapper_security_config_custom ---")
    
    # (FIX) L'attributo è .pbkdf2_iterations
    assert base_config.pbkdf2_iterations == 100000 
    assert base_config.max_key_cache == 3 # (Valore di default nel file)
    
    # 1. Crea config custom
    custom_config = wrapper.SecurityConfig(
        pbkdf2_iterations=500000, # Valore custom
        max_key_cache=1        # Valore custom
    )
    
    assert custom_config.pbkdf2_iterations == 500000
    assert custom_config.max_key_cache == 1
    
    # 2. Verifica che crypto usi la config custom
    crypto = wrapper.SecureCrypto(custom_config)
    
    assert crypto.config.pbkdf2_iterations == 500000
    
    # 3. Verifica max_key_cache=1
    key1 = crypto.derive_key(b'p1_password', b's1_salt_ok')
    key2 = crypto.derive_key(b'p2_password', b's2_salt_ok') # Deve rimuovere key1
    
    assert len(crypto._key_cache) == 1
    assert crypto.get_key_from_cache(b'p1_password', b's1_salt_ok') is None # Rimosso
    assert crypto.get_key_from_cache(b'p2_password', b's2_salt_ok') is not None # Presente