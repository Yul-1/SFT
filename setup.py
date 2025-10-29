#!/usr/bin/env python3
"""
Script di build per l'estensione C di AegisTransfer (crypto_accelerator)
Gestisce la compilazione MSVC (Windows) e GCC/Clang (Linux/macOS)
"""

import os
import sys
from setuptools import setup, Extension

# --- Configurazione OpenSSL ---
# Su Windows, usa OpenSSL installato da vcpkg

if sys.platform == "win32":
    vcpkg_root = os.environ.get('VCPKG_ROOT', 'C:\\vcpkg')
    vcpkg_installed = os.path.join(vcpkg_root, 'installed', 'x64-windows')
    
    if not os.path.exists(vcpkg_installed):
        print("------------------------------------------------------------", file=sys.stderr)
        print("ERRORE: OpenSSL non trovato in vcpkg.", file=sys.stderr)
        print("Assicurati di aver installato OpenSSL con:", file=sys.stderr)
        print("  vcpkg install openssl:x64-windows", file=sys.stderr)
        print("------------------------------------------------------------", file=sys.stderr)
        sys.exit(1)
    
    print(f"--- Usando OpenSSL da vcpkg: {vcpkg_installed} ---")
    
    # Usa OpenSSL da vcpkg
    include_dirs = [os.path.join(vcpkg_installed, 'include')]
    library_dirs = [os.path.join(vcpkg_installed, 'lib')]
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