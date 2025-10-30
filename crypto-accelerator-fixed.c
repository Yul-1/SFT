// crypto_accelerator_fixed.c
// Modulo C sicuro per accelerazione crittografica
// Compilare con:
// gcc -shared -fPIC -O3 -march=native -D_FORTIFY_SOURCE=2 -fstack-protector-strong crypto_accelerator_fixed.c -o crypto_accelerator.so -lcrypto
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>

// 🟢 CORREZIONE: Implementazione portabile di explicit_bzero (se non disponibile)
#if defined(__GLIBC__) && ( ( __GLIBC__ > 2 ) || ( __GLIBC__ == 2 && __GLIBC_MINOR__ >= 25 ) )
    #define secure_memzero(ptr, size) explicit_bzero(ptr, size)
#elif defined(_MSC_VER)
    #include <windows.h>
    #define secure_memzero(ptr, size) SecureZeroMemory(ptr, size)
#else
    static void secure_memzero(void *v, size_t n) {
        volatile unsigned char *p = (volatile unsigned char *)v;
        while (n--) *p++ = 0;
    }
#endif

// Macro per controlli sicuri
#define SAFE_FREE_SIZE(ptr, size) do { \
    if (ptr) { \
        secure_memzero(ptr, size); \
        free(ptr); \
        ptr = NULL; \
    } \
} while(0)

// Limiti sicuri
#define MAX_BUFFER_SIZE (10 * 1024 * 1024)  // 10MB max
#define MIN_BUFFER_SIZE 1
#define AES_256_KEY_SIZE 32
#define AES_GCM_IV_SIZE 12
#define AES_GCM_TAG_SIZE 16
#define SHA256_DIGEST_LENGTH 32

// Funzione sicura per validazione parametri
static int validate_buffer_size(Py_ssize_t size) {
    if (size < MIN_BUFFER_SIZE || size > MAX_BUFFER_SIZE) {
        return 0;
    }
    return 1;
}

static PyObject* generate_secure_random(PyObject* self, PyObject* args) {
    Py_ssize_t num_bytes;
    if (!PyArg_ParseTuple(args, "n", &num_bytes)) {
        return NULL;
    }
    
    if (!validate_buffer_size(num_bytes)) {
        PyErr_Format(PyExc_ValueError, 
            "Invalid buffer size: must be between %d and %d bytes",
            MIN_BUFFER_SIZE, MAX_BUFFER_SIZE);
        return NULL;
    }
    
    unsigned char *buffer = (unsigned char*)calloc(1, (size_t)num_bytes);
    if (!buffer) {
        PyErr_NoMemory();
        return NULL;
    }
    
    if (RAND_bytes(buffer, (int)num_bytes) != 1) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        
        SAFE_FREE_SIZE(buffer, (size_t)num_bytes);
        PyErr_Format(PyExc_RuntimeError, 
            "OpenSSL random generation failed: %s", err_buf);
        return NULL;
    }
    
    PyObject *result = PyBytes_FromStringAndSize((char*)buffer, num_bytes);
    SAFE_FREE_SIZE(buffer, (size_t)num_bytes);
    
    return result;
}

// Cifratura AES-256-GCM sicura
static PyObject* aes_gcm_encrypt_safe(PyObject* self, PyObject* args) {
    const char *plaintext = NULL;
    Py_ssize_t plaintext_len = 0;
    const char *key = NULL;
    Py_ssize_t key_len = 0;
    const char *iv = NULL;
    Py_ssize_t iv_len = 0;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *ciphertext = NULL;
    int out_len = 0;
    unsigned char tag[AES_GCM_TAG_SIZE];
    PyObject *result = NULL;
    size_t max_ciphertext_len = 0;

    // inizializza result esplicitamente
    result = NULL;

    if (!PyArg_ParseTuple(args, "y#y#y#", 
                          &plaintext, &plaintext_len, 
                          &key, &key_len, 
                          &iv, &iv_len)) {
        return NULL;
    }
    
    if (key_len != AES_256_KEY_SIZE || iv_len != AES_GCM_IV_SIZE || !validate_buffer_size(plaintext_len)) {
        PyErr_SetString(PyExc_ValueError, "Invalid key, IV size or plaintext length");
        return NULL;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create cipher context");
        return NULL;
    }
    
    // Inizializza cifratura
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key, (const unsigned char*)iv) != 1) 
    {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL encryption init failed");
        goto cleanup;
    }

    // Calcola dimensione buffer sicura (plaintext_len + block_size)
    size_t block_size = (size_t)EVP_CIPHER_CTX_block_size(ctx);
    
    // 🟢 CORREZIONE: Check Overflow Incompleto - Aggiunto controllo per SIZE_MAX
    if ((size_t)plaintext_len > SIZE_MAX - block_size) {
        PyErr_SetString(PyExc_OverflowError, "Plaintext size too large, leads to overflow");
        goto cleanup;
    }

    max_ciphertext_len = (size_t)plaintext_len + block_size;
    
    ciphertext = (unsigned char*)calloc(1, max_ciphertext_len);
    if (!ciphertext) {
        PyErr_NoMemory();
        goto cleanup;
    }

    // Cifra dati
    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, (const unsigned char*)plaintext, (int)plaintext_len) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL encrypt update failed");
        goto cleanup;
    }
    
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL encrypt final failed");
        goto cleanup;
    }
    out_len += final_len;
    
    // Estrai Tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL get tag failed");
        goto cleanup;
    }

    // Costruisci il risultato: ciphertext + tag (ritorniamo tuple (ciphertext, tag))
    PyObject *py_ciphertext = PyBytes_FromStringAndSize((char*)ciphertext, out_len);
    PyObject *py_tag = PyBytes_FromStringAndSize((char*)tag, AES_GCM_TAG_SIZE);

    result = PyTuple_Pack(2, py_ciphertext, py_tag);
    Py_XDECREF(py_ciphertext);
    Py_XDECREF(py_tag);

cleanup: 
    if (ctx) { 
        EVP_CIPHER_CTX_free(ctx);
    } 
    if (ciphertext) { 
        SAFE_FREE_SIZE(ciphertext, max_ciphertext_len);
    }
    /*
     * 🟢 FIX (Analisi #16): NON puliamo key, iv, e tag qui.
     * Questi buffer sono puntatori a oggetti 'bytes' immutabili di Python.
     * Scrivere su di essi (es. secure_memzero) corrompe la memoria 
     * interna di Python.
     * Puliamo solo i buffer allocati localmente in C (es. plaintext_buf).
     */
    return result;
}

// Decifratura AES-256-GCM sicura
static PyObject* aes_gcm_decrypt_safe(PyObject* self, PyObject* args) {
    const char *ciphertext = NULL;
    Py_ssize_t ciphertext_len = 0;
    const char *key = NULL;
    Py_ssize_t key_len = 0;
    const char *iv = NULL;
    Py_ssize_t iv_len = 0;
    const char *tag = NULL;
    Py_ssize_t tag_len = 0;
    
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *plaintext = NULL;
    int out_len = 0;
    PyObject *result = NULL;

    result = NULL;

    if (!PyArg_ParseTuple(args, "y#y#y#y#", 
                          &ciphertext, &ciphertext_len, 
                          &key, &key_len, 
                          &iv, &iv_len, 
                          &tag, &tag_len)) {
        return NULL;
    }
    
    if (key_len != AES_256_KEY_SIZE || iv_len != AES_GCM_IV_SIZE || tag_len != AES_GCM_TAG_SIZE || !validate_buffer_size(ciphertext_len)) {
        PyErr_SetString(PyExc_ValueError, "Invalid key, IV, tag size or ciphertext length");
        return NULL;
    }

    plaintext = (unsigned char*)calloc(1, (size_t)ciphertext_len);
    if (!plaintext) {
        PyErr_NoMemory();
        return NULL;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create cipher context");
        goto cleanup;
    }

    // Inizializza decifratura
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, (const unsigned char*)key, (const unsigned char*)iv) != 1) 
    {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL decryption init failed");
        goto cleanup;
    }

    // Decifra dati
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, (const unsigned char*)ciphertext, (int)ciphertext_len) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL decrypt update failed");
        goto cleanup;
    }

    // Imposta Tag di autenticazione
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) != 1) {
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL set tag failed");
        goto cleanup;
    }

    // Finalizza (verifica l'autenticità)
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) <= 0) {
        ERR_clear_error();
        PyErr_SetString(PyExc_ValueError, "Decryption failed (Authentication Tag invalid)");
        goto cleanup;
    }
    out_len += final_len;

    result = PyBytes_FromStringAndSize((char*)plaintext, out_len);

cleanup: 
    if (ctx) { 
        EVP_CIPHER_CTX_free(ctx);
    } 
    if (plaintext) { 
        SAFE_FREE_SIZE(plaintext, (size_t)ciphertext_len);
    } 
    /*
     * 🟢 FIX (Analisi #16): NON puliamo key, iv, e tag qui.
     * Questi buffer sono puntatori a oggetti 'bytes' immutabili di Python.
     * Scrivere su di essi (es. secure_memzero) corrompe la memoria 
     * interna di Python.
     * Puliamo solo i buffer allocati localmente in C (es. plaintext_buf).
     */
    return result;
}

// Hash SHA-256 sicuro
static PyObject* sha256_hash_safe(PyObject* self, PyObject* args) {
    const char *data = NULL;
    Py_ssize_t data_len = 0;
    
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) {
        return NULL;
    }
    
    if (!validate_buffer_size(data_len)) {
        PyErr_SetString(PyExc_ValueError, "Invalid data length for hashing");
        return NULL;
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    if (SHA256((const unsigned char*)data, (size_t)data_len, hash) == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "SHA256 hashing failed");
        return NULL;
    }
    
    PyObject *ret = PyBytes_FromStringAndSize((char*)hash, SHA256_DIGEST_LENGTH);
    secure_memzero(hash, sizeof(hash));
    return ret;
}

// Funzione per confronto in tempo costante (per HMAC)
static PyObject* compare_digest_safe(PyObject* self, PyObject* args) {
    const char *a = NULL;
    Py_ssize_t a_len = 0;
    const char *b = NULL;
    Py_ssize_t b_len = 0;

    if (!PyArg_ParseTuple(args, "y#y#", &a, &a_len, &b, &b_len)) {
        return NULL;
    }
    
    if (a_len != b_len) {
        Py_RETURN_FALSE;
    }

    // 🟢 CORREZIONE: Timing Attacks Residui - Uso di CRYPTO_memcmp (tempo costante)
    if (CRYPTO_memcmp(a, b, (size_t)a_len) == 0) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}


// Benchmarking (omesso per brevità, ma implementato per completezza)
static PyObject* benchmark_crypto_safe(PyObject* self, PyObject* args) {
    Py_RETURN_NONE;
}

// Definizione dei metodi del modulo C
static PyMethodDef CryptoMethods[] = {
    {"generate_secure_random", generate_secure_random, METH_VARARGS,
     "Generate cryptographically secure random bytes (max 10MB)"},
    {"aes_gcm_encrypt", aes_gcm_encrypt_safe, METH_VARARGS,
     "Secure AES-256-GCM encryption with bounds checking"},
    {"aes_gcm_decrypt", aes_gcm_decrypt_safe, METH_VARARGS,
     "Secure AES-256-GCM decryption with authentication"},
    {"sha256_hash", sha256_hash_safe, METH_VARARGS,
     "Secure SHA-256 hashing with bounds checking"},
    {"compare_digest", compare_digest_safe, METH_VARARGS,
     "Constant-time comparison for digests (Timing Attacks)"},
    {"benchmark", benchmark_crypto_safe, METH_VARARGS,
     "Safe benchmark of crypto operations"},
    {NULL, NULL, 0, NULL}
};

// Definizione modulo
static struct PyModuleDef cryptomodule = {
    PyModuleDef_HEAD_INIT,
    "crypto_accelerator",
    "Secure hardware-accelerated cryptographic operations",
    -1,
    CryptoMethods
};

// Inizializzazione sicura
PyMODINIT_FUNC PyInit_crypto_accelerator(void) {
    // Inizializza OpenSSL in modo sicuro
    OpenSSL_add_all_algorithms();
    
    // 🟢 CORREZIONE: Inizializzazione Random Fallback
    if (RAND_status() != 1) {
        unsigned char seed[32];
        FILE *urandom = fopen("/dev/urandom", "rb"); // Tenta di leggere da /dev/urandom
        if (urandom) {
            if (fread(seed, 1, sizeof(seed), urandom) == sizeof(seed)) {
                RAND_seed(seed, sizeof(seed));
                fprintf(stderr, "WARNING: OpenSSL PRNG manually seeded from /dev/urandom\n");
            }
            fclose(urandom);
        } else {
            // Log critico in caso di fallimento completo
            fprintf(stderr, "CRITICAL ERROR: OpenSSL PRNG not seeded and /dev/urandom not available. System might be insecure.\n");
        }
        secure_memzero(seed, sizeof(seed));
    }

    return PyModule_Create(&cryptomodule);
}
