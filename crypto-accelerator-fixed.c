// crypto_accelerator_fixed.c
// Modulo C sicuro per accelerazione crittografica
// Compilare con:
// gcc -shared -fPIC -O3 -march=native -D_FORTIFY_SOURCE=2 -fstack-protector-strong crypto_accelerator_fixed.c -o crypto_accelerator.so -lcrypto
#define PY_SSIZE_T_CLEAN
#include <Python.h>
// 🟢 FIX (Analisi #1)
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
#define CHECK_PTR(ptr) if (ptr == NULL) { PyErr_SetString(PyExc_MemoryError, "OpenSSL allocation failed"); goto cleanup; }
#define CHECK_SSL_SUCCESS(ret) if (ret <= 0) { PyErr_SetString(PyExc_ValueError, "OpenSSL operation failed"); goto cleanup; }

// Definizioni costanti (per coerenza con il wrapper)
// 🟢 FIX: 0 è una lunghezza valida per encrypt/hash
#define MIN_PY_BUFFER_SIZE 0
#define MAX_PY_BUFFER_SIZE (10 * 1024 * 1024)

// 🟢 CORREZIONE: Funzione helper per validazione
static int validate_buffer_size(Py_ssize_t size, Py_ssize_t min, Py_ssize_t max, const char* name) {
    if (size > max || size < min) {
        PyErr_Format(PyExc_ValueError, "Invalid %s size: %zd. Must be between %zd and %zd bytes.",
                     name, size, min, max);
        return 0; // Fallito
    }
    return 1; // Successo
}


// --- Funzioni Crittografiche Sicure ---

/*
 * Cifra AES-GCM (PyBytes -> PyTuple(bytes, bytes))
 */
static PyObject* aes_gcm_encrypt_safe(PyObject* self, PyObject* args) {
    PyObject* result_tuple = NULL;
    PyObject* ciphertext_obj = NULL;
    PyObject* tag_obj = NULL;
    
    const unsigned char *plaintext = NULL;
    const unsigned char *key = NULL;
    const unsigned char *iv = NULL;
    Py_ssize_t plaintext_len, key_len, iv_len;

    // Buffer C
    unsigned char *ciphertext_buf = NULL;
    unsigned char *tag_buf = NULL;
    
    // Contesto OpenSSL
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ciphertext_len;

    // 1. Parse argomenti (y# = bytes read-only)
    if (!PyArg_ParseTuple(args, "y#y#y#", &plaintext, &plaintext_len, &key, &key_len, &iv, &iv_len)) {
        return NULL; // TypeError sollevato da ParseTuple
    }

    // 2. Validazione rigorosa dimensioni
    if (key_len != 32 || iv_len != 12) {
        PyErr_SetString(PyExc_ValueError, "Invalid key, IV size or plaintext length");
        return NULL;
    }
    // 🟢 FIX: Usa MIN_PY_BUFFER_SIZE (ora 0)
    if (!validate_buffer_size(plaintext_len, MIN_PY_BUFFER_SIZE, MAX_PY_BUFFER_SIZE, "plaintext")) {
        return NULL;
    }

    // 3. Allocazione buffer
    ciphertext_buf = (unsigned char*)PyMem_Malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    tag_buf = (unsigned char*)PyMem_Malloc(16); // GCM tag 16 byte
    if (ciphertext_buf == NULL || tag_buf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory");
        goto cleanup;
    }
    
    // 4. Inizializza contesto
    ctx = EVP_CIPHER_CTX_new();
    CHECK_PTR(ctx);

    // 5. Setup Cifra (AES-256-GCM)
    CHECK_SSL_SUCCESS(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    CHECK_SSL_SUCCESS(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));

    // 6. Cifra
    // (GCM non ha AAD qui)
    CHECK_SSL_SUCCESS(EVP_EncryptUpdate(ctx, ciphertext_buf, &len, plaintext, (int)plaintext_len));
    ciphertext_len = len;

    // 7. Finalizza
    CHECK_SSL_SUCCESS(EVP_EncryptFinal_ex(ctx, ciphertext_buf + len, &len));
    ciphertext_len += len;

    // 8. Ottieni il TAG GCM
    CHECK_SSL_SUCCESS(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf));

    // 9. Crea oggetti PyBytes (copia)
    ciphertext_obj = PyBytes_FromStringAndSize((char*)ciphertext_buf, ciphertext_len);
    tag_obj = PyBytes_FromStringAndSize((char*)tag_buf, 16);
    
    // 10. Crea Tupla risultato
    result_tuple = PyTuple_Pack(2, ciphertext_obj, tag_obj);

cleanup:
    // Pulizia sicura
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ciphertext_buf) {
        secure_memzero(ciphertext_buf, plaintext_len + EVP_MAX_BLOCK_LENGTH);
        PyMem_Free(ciphertext_buf);
    }
    if (tag_buf) {
        secure_memzero(tag_buf, 16);
        PyMem_Free(tag_buf);
    }
    
    // Pulisci ref (anche se 0, Py_XDECREF è sicuro)
    Py_XDECREF(ciphertext_obj);
    Py_XDECREF(tag_obj);
    
    // 🟢 FIX (Analisi #16): NON puliamo key, iv (buffer Python)

    return result_tuple; // Può essere NULL in caso di errore
}

/*
 * Decifra AES-GCM (PyBytes -> PyBytes)
 */
static PyObject* aes_gcm_decrypt_safe(PyObject* self, PyObject* args) {
    PyObject* plaintext_obj = NULL;
    
    const unsigned char *ciphertext = NULL;
    const unsigned char *key = NULL;
    const unsigned char *iv = NULL;
    const unsigned char *tag = NULL;
    Py_ssize_t ciphertext_len, key_len, iv_len, tag_len;

    // Buffer C
    unsigned char *plaintext_buf = NULL;
    
    // Contesto OpenSSL
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;
    
    // 1. Parse argomenti
    if (!PyArg_ParseTuple(args, "y#y#y#y#", &ciphertext, &ciphertext_len, &key, &key_len, &iv, &iv_len, &tag, &tag_len)) {
        return NULL;
    }

    // 2. Validazione rigorosa dimensioni
    if (key_len != 32 || iv_len != 12 || tag_len != 16) {
        PyErr_SetString(PyExc_ValueError, "Invalid key, IV or tag size");
        return NULL;
    }
    // 🟢 FIX: Usa MIN_PY_BUFFER_SIZE (ora 0)
    if (!validate_buffer_size(ciphertext_len, MIN_PY_BUFFER_SIZE, MAX_PY_BUFFER_SIZE, "ciphertext")) {
        return NULL;
    }

    // 3. Allocazione buffer
    // (Dimensione massima = ciphertext_len + block_size)
    plaintext_buf = (unsigned char*)PyMem_Malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    if (plaintext_buf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory");
        goto cleanup;
    }

    // 4. Inizializza contesto
    ctx = EVP_CIPHER_CTX_new();
    CHECK_PTR(ctx);

    // 5. Setup Cifra (AES-256-GCM)
    CHECK_SSL_SUCCESS(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));
    CHECK_SSL_SUCCESS(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

    // 6. Decifra
    CHECK_SSL_SUCCESS(EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext, (int)ciphertext_len));
    plaintext_len = len;

    // 7. Imposta il TAG (necessario PRIMA di Finalize)
    CHECK_SSL_SUCCESS(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag));

    // 8. Finalizza (Verifica autenticazione)
    // Se il tag è errato, questa chiamata fallisce (ritorna <= 0)
    // e solleva l'errore in CHECK_SSL_SUCCESS
    if (EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len) <= 0) {
        PyErr_SetString(PyExc_ValueError, "Decryption failed (Authentication Tag Mismatch or corrupted data)");
        goto cleanup;
    }
    plaintext_len += len;

    // 9. Crea oggetto PyBytes (copia)
    plaintext_obj = PyBytes_FromStringAndSize((char*)plaintext_buf, plaintext_len);
    
cleanup:
    // Pulizia sicura
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plaintext_buf) {
        secure_memzero(plaintext_buf, ciphertext_len + EVP_MAX_BLOCK_LENGTH);
        PyMem_Free(plaintext_buf);
    }
    
    // 🟢 FIX (Analisi #16): NON puliamo key, iv, tag (buffer Python)

    return plaintext_obj; // Può essere NULL in caso di errore
}

/*
 * Genera Random (int -> PyBytes)
 */
static PyObject* generate_secure_random_safe(PyObject* self, PyObject* args) {
    Py_ssize_t num_bytes;
    PyObject* random_bytes_obj = NULL;
    unsigned char *random_buf = NULL;

    // 1. Parse argomenti
    if (!PyArg_ParseTuple(args, "n", &num_bytes)) {
        return NULL;
    }

    // 2. Valida la dimensione richiesta
    // 🟢 FIX: 'generate_random' richiede MIN 1, anche se encrypt/hash permettono 0.
    if (!validate_buffer_size(num_bytes, 1, MAX_PY_BUFFER_SIZE, "buffer")) {
        return NULL;
    }

    // 3. Allocazione buffer
    random_buf = (unsigned char*)PyMem_Malloc(num_bytes);
    if (random_buf == NULL) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory");
        goto cleanup;
    }

    // 4. Genera random
    if (RAND_bytes(random_buf, (int)num_bytes) != 1) {
        PyErr_SetString(PyExc_SystemError, "OpenSSL RAND_bytes failed (PRNG not seeded?)");
        goto cleanup;
    }

    // 5. Crea oggetto PyBytes (copia)
    random_bytes_obj = PyBytes_FromStringAndSize((char*)random_buf, num_bytes);

cleanup:
    // Pulizia sicura
    if (random_buf) {
        secure_memzero(random_buf, num_bytes);
        PyMem_Free(random_buf);
    }
    return random_bytes_obj;
}

/*
 * Hash SHA-256 (PyBytes -> PyBytes)
 */
static PyObject* sha256_hash_safe(PyObject* self, PyObject* args) {
    const unsigned char *data;
    Py_ssize_t data_len;
    unsigned char hash_buf[SHA256_DIGEST_LENGTH];

    // 1. Parse argomenti
    if (!PyArg_ParseTuple(args, "y#", &data, &data_len)) {
        return NULL;
    }

    // 2. Validazione (usa MIN_PY_BUFFER_SIZE, ora 0)
    if (!validate_buffer_size(data_len, MIN_PY_BUFFER_SIZE, MAX_PY_BUFFER_SIZE, "data for hashing")) {
        return NULL;
    }

    // 3. Hash
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        PyErr_SetString(PyExc_MemoryError, "EVP_MD_CTX_new failed");
        return NULL;
    }

    if (1 != EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) ||
        1 != EVP_DigestUpdate(md_ctx, data, data_len) ||
        1 != EVP_DigestFinal_ex(md_ctx, hash_buf, NULL)) {
        
        EVP_MD_CTX_free(md_ctx);
        PyErr_SetString(PyExc_SystemError, "OpenSSL SHA-256 operation failed");
        return NULL;
    }

    EVP_MD_CTX_free(md_ctx);

    // 4. Return PyBytes (copia)
    return PyBytes_FromStringAndSize((char*)hash_buf, SHA256_DIGEST_LENGTH);
}

/*
 * Confronto sicuro (Timing Attack Safe)
 */
static PyObject* compare_digest_safe(PyObject* self, PyObject* args) {
    const unsigned char *a, *b;
    Py_ssize_t a_len, b_len;

    if (!PyArg_ParseTuple(args, "y#y#", &a, &a_len, &b, &b_len)) {
        return NULL;
    }
    
    // (Non validiamo MAX_BUFFER_SIZE qui, confronto semplice)
    if (a_len < 0 || b_len < 0) {
        PyErr_SetString(PyExc_ValueError, "Invalid lengths");
        return NULL;
    }

    // 🟢 FIX: Logica di confronto robusta
    int match = 0; // 0 = False (non corrispondono)
    
    if (a_len == b_len) {
        // Solo se le lunghezze sono uguali, esegui il confronto sicuro
        if (CRYPTO_memcmp(a, b, a_len) == 0) {
             // CRYPTO_memcmp ritorna 0 SE corrispondono
            match = 1; // 1 = True (corrispondono)
        }
    }
    
    // Se le lunghezze sono diverse, 'match' rimane 0 (False)
    
    if (match == 1) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

/*
 * Benchmark (placeholder)
 */
static PyObject* benchmark_crypto_safe(PyObject* self, PyObject* args) {
    // Placeholder se necessario
    Py_RETURN_NONE;
}

// --- Definizione Metodi e Modulo ---

static PyMethodDef CryptoMethods[] = {
    {"aes_gcm_encrypt", aes_gcm_encrypt_safe, METH_VARARGS,
     "Secure AES-GCM encryption with bounds checking"},
    {"aes_gcm_decrypt", aes_gcm_decrypt_safe, METH_VARARGS,
     "Secure AES-GCM decryption with auth tag checking"},
    {"generate_secure_random", generate_secure_random_safe, METH_VARARGS,
     "Generate cryptographically secure random bytes"},
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
            // 🟢 FIX (Analisi #11): Loop per garantire lettura completa
            size_t total_read = 0;
            while (total_read < sizeof(seed)) {
                size_t read_now = fread(seed + total_read, 1, sizeof(seed) - total_read, urandom);
                if (read_now == 0) {
                    // EOF o errore prima di riempire il seed
                    fprintf(stderr, "CRITICAL ERROR: Failed to read sufficient bytes from /dev/urandom\n");
                    break;
                }
                total_read += read_now;
            }
            
            if (total_read == sizeof(seed)) {
                RAND_seed(seed, sizeof(seed));
                fprintf(stderr, "WARNING: OpenSSL PRNG manually seeded from /dev/urandom\n");
            }
            fclose(urandom);
        } else {
            // Log critico in caso di fallimento completo
            fprintf(stderr, "CRITICAL ERROR: OpenSSL PRNG not seeded AND /dev/urandom not found.\n");
        }
        // Pulizia seed
        secure_memzero(seed, sizeof(seed));
    }

    return PyModule_Create(&cryptomodule);
}