#!/usr/bin/env python3
"""
Script di build per l'estensione C di AegisTransfer (crypto_accelerator)
Gestisce la compilazione MSVC (Windows) e GCC/Clang (Linux/macOS)
"""

import os
import sys
from setuptools import setup, Extension

# --- Configurazione OpenSSL ---
# Cerca OpenSSL in percorsi comuni o tramite variabili d'ambiente
# Su Windows, imposta OPENSSL_ROOT_DIR o VCPKG_ROOT

vcpkg_root = os.environ.get('VCPKG_ROOT')
openssl_dir = os.environ.get('OPENSSL_ROOT_DIR')

if sys.platform == "win32":
    if not openssl_dir and vcpkg_root:
        # Percorso standard di vcpkg per installazioni x64
        openssl_dir = os.path.join(vcpkg_root, 'installed', 'x64-windows')
    
    if not openssl_dir or not os.path.exists(openssl_dir):
        print("------------------------------------------------------------", file=sys.stderr)
        print("ERRORE: OpenSSL non trovato.", file=sys.stderr)
        print("Per favore, installa OpenSSL (es. 'vcpkg install openssl:x64-windows')", file=sys.stderr)
        print("e imposta la variabile d'ambiente OPENSSL_ROOT_DIR.", file=sys.stderr)
        print(f" (Cercato in: {openssl_dir})", file=sys.stderr)
        print("------------------------------------------------------------", file=sys.stderr)
        sys.exit(1)

    print(f"--- Trovato OpenSSL in: {openssl_dir} ---")
    
    include_dirs = [os.path.join(openssl_dir, 'include')]
    library_dirs = [os.path.join(openssl_dir, 'lib')]
    libraries = ['libcrypto', 'libssl']
    
    # Flag specifici per MSVC (anche se setuptools ne gestisce molti)
    extra_compile_args = ['/O2', '/D_FORTIFY_SOURCE=2']
    extra_link_args = []

else:
    # Impostazioni per Linux/macOS
    include_dirs = ['/usr/local/opt/openssl/include', '/usr/include']
    library_dirs = ['/usr/local/opt/openssl/lib', '/usr/lib', '/lib']
    libraries = ['crypto', 'ssl']
    
    extra_compile_args = [
        '-fPIC', '-O3', '-march=native', 
        '-D_FORTIFY_SOURCE=2', '-fstack-protector-strong'
    ]
    extra_link_args = ['-Wl,-z,relro,-z,now']

# --- Definizione Estensione ---

crypto_module = Extension(
    'crypto_accelerator',
    sources=['crypto-accelerator-fixed.c'],
    include_dirs=include_dirs,
    library_dirs=library_dirs,
    libraries=libraries,
    extra_compile_args=extra_compile_args,
    extra_link_args=extra_link_args
)

setup(
    name='AegisCryptoAccelerator',
    version='1.0',
    description='Modulo di accelerazione C per AegisTransfer',
    ext_modules=[crypto_module]
)