#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "tlsrepair.h"
#include <curl/curl.h>
#include <limits.h>
#include <stdint.h>

#define TLSREPAIR_MAX_AIA_DEPTH 8

struct Memory {
    unsigned char *data;
    size_t size;
};

struct TLSRepair {
    CURL *curl;
    char *url;
    int owns_curl;
    char *proxy;
    STACK_OF(X509) *aia_certificates;
    int repaired;
    char *error;
};

static void set_error(
    TLSRepair *repair,
    const char *message
);

static void set_curl_error(
    TLSRepair *repair,
    const char *operation,
    CURLcode result
)
{
    char error_message[256];

    snprintf(
        error_message,
        sizeof(error_message),
        "%s: %d (%s)",
        operation,
        result,
        curl_easy_strerror(result)
    );

    set_error(
        repair,
        error_message
    );
}

static void set_error(
    TLSRepair *repair,
    const char *message
)
{
    if(!repair){
        return;
    }

    free(repair->error);

    repair->error = NULL;

    if(!message){
        return;
    }

    repair->error =
        malloc(
            strlen(message) + 1
        );

    if(!repair->error){
        return;
    }

    strcpy(
        repair->error,
        message
    );
}

const char *tlsrepair_error(
    TLSRepair *repair
)
{
    if(!repair){
        return NULL;
    }

    return repair->error;
}

static size_t write_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    struct Memory *memory = userp;

    if(nmemb != 0 &&
       size > SIZE_MAX / nmemb){

        return 0;
    }

    size_t total = size * nmemb;

    if(memory->size > SIZE_MAX - total - 1){

        return 0;
    }

    unsigned char *new_data =
        realloc(
            memory->data,
            memory->size + total + 1
        );

    if(!new_data){
        return 0;
    }

    memory->data = new_data;

    memcpy(
        memory->data + memory->size,
        contents,
        total
    );

    memory->size += total;

    memory->data[memory->size] = '\0';

    return total;
}

static size_t discard_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    (void)contents;
    (void)userp;

    if(nmemb != 0 &&
        size > SIZE_MAX / nmemb){

        return 0;
    }

    return size * nmemb;
}

static X509 *parse_certificate(
    TLSRepair *repair,
    const char *data
)
{
    if(!data){
        set_error(
            repair,
            "invalid certificate data"
        );

        return NULL;
    }

    const char *pem =
        strstr(
            data,
            "-----BEGIN CERTIFICATE-----"
        );

    if(!pem){
        set_error(
            repair,
            "certificate PEM data not found"
        );

        return NULL;
    }

    BIO *bio =
        BIO_new_mem_buf(
            pem,
            -1
        );

    if(!bio){
        set_error(
            repair,
            "failed to create certificate memory BIO"
        );

        return NULL;
    }

    X509 *cert =
        PEM_read_bio_X509(
            bio,
            NULL,
            NULL,
            NULL
        );

    BIO_free(bio);

    if(!cert){
        set_error(
            repair,
            "failed to parse PEM certificate"
        );

        return NULL;
    }

    return cert;
}

static X509 *parse_certificate_memory(
    TLSRepair *repair,
    const unsigned char *data,
    size_t size
)
{
    if(!data || size == 0){
        set_error(
            repair,
            "invalid certificate data"
        );

        return NULL;
    }

    if(size > LONG_MAX ||
       size > INT_MAX){

        set_error(
            repair,
            "certificate data is too large"
        );

        return NULL;
    }

    const unsigned char *ptr = data;

    X509 *cert =
        d2i_X509(
            NULL,
            &ptr,
            (long)size
        );

    if(cert){
        return cert;
    }

    BIO *bio =
        BIO_new_mem_buf(
            data,
            (int)size
        );

    if(!bio){
        set_error(
            repair,
            "failed to create certificate memory BIO"
        );

        return NULL;
    }

    cert =
        PEM_read_bio_X509(
            bio,
            NULL,
            NULL,
            NULL
        );

    BIO_free(bio);

    if(!cert){
        set_error(
            repair,
            "failed to parse certificate"
        );

        return NULL;
    }

    return cert;
}

static STACK_OF(X509) *parse_certificates(
    TLSRepair *repair,
    struct curl_certinfo *certInfo
)
{
    if(!certInfo){
        set_error(
            repair,
            "certificate information is unavailable"
        );

        return NULL;
    }

    STACK_OF(X509) *certificates =
        sk_X509_new_null();

    if(!certificates){
        set_error(
            repair,
            "failed to create certificate stack"
        );

        return NULL;
    }

    for(int i = 0;
        i < certInfo->num_of_certs;
        i++){

        struct curl_slist *item =
            certInfo->certinfo[i];

        while(item){

            if(item->data &&
               strstr(
                   item->data,
                   "-----BEGIN CERTIFICATE-----"
               )){

                X509 *cert =
                    parse_certificate(
                        repair,
                        item->data
                    );

                if(!cert){
                    item = item->next;
                    continue;
                }

                if(!sk_X509_push(
                    certificates,
                    cert
                )){

                    set_error(
                        repair,
                        "failed to add certificate to certificate stack"
                    );

                    X509_free(cert);

                    sk_X509_pop_free(
                        certificates,
                        X509_free
                    );

                    return NULL;
                }
            }

            item = item->next;
        }
    }

    return certificates;
}

static X509_STORE *create_trust_store(
    TLSRepair *repair
)
{
    X509_STORE *store =
        X509_STORE_new();

    if(!store){
        set_error(
            repair,
            "failed to create certificate trust store"
        );

        return NULL;
    }

    if(X509_STORE_set_default_paths(
        store
    ) != 1){

        set_error(
            repair,
            "failed to load default certificate trust store paths"
        );

        X509_STORE_free(store);

        return NULL;
    }

    return store;
}

static STACK_OF(X509) *create_untrusted_stack(
    TLSRepair *repair,
    STACK_OF(X509) *certificates
)
{
    if(!certificates){
        set_error(
            repair,
            "certificate stack is unavailable"
        );

        return NULL;
    }

    STACK_OF(X509) *untrusted =
        sk_X509_new_null();

    if(!untrusted){
        set_error(
            repair,
            "failed to create untrusted certificate stack"
        );

        return NULL;
    }

    for(int i = 1;
        i < sk_X509_num(certificates);
        i++){

        X509 *cert =
            sk_X509_value(
                certificates,
                i
            );

        if(!cert){
            continue;
        }

        if(X509_up_ref(cert) != 1){

            set_error(
                repair,
                "failed to increase certificate reference"
            );

            sk_X509_pop_free(
                untrusted,
                X509_free
            );

            return NULL;
        }

        if(!sk_X509_push(
            untrusted,
            cert
        )){

            set_error(
                repair,
                "failed to add certificate to untrusted certificate stack"
            );

            sk_X509_pop_free(
                untrusted,
                X509_free
            );

            return NULL;
        }
    }

    return untrusted;
}

static int verify_certificate_chain(
    TLSRepair *repair,
    X509 *leaf,
    X509_STORE *store,
    STACK_OF(X509) *untrusted
)
{
    if(!leaf || !store){
        set_error(
            repair,
            "invalid certificate verification parameters"
        );

        return -1;
    }

    X509_STORE_CTX *ctx =
        X509_STORE_CTX_new();

    if(!ctx){
        set_error(
            repair,
            "failed to create certificate verification context"
        );

        return -1;
    }

    if(X509_STORE_CTX_init(
        ctx,
        store,
        leaf,
        untrusted
    ) != 1){

        set_error(
            repair,
            "failed to initialize certificate verification context"
        );

        X509_STORE_CTX_free(ctx);

        return -1;
    }

    int result =
        X509_verify_cert(ctx);

    if(result != 1){

        int error =
            X509_STORE_CTX_get_error(ctx);

        char error_message[256];

        snprintf(
            error_message,
            sizeof(error_message),
            "certificate verification failed: %d (%s)",
            error,
            X509_verify_cert_error_string(error)
        );

        set_error(
            repair,
            error_message
        );
    }

    X509_STORE_CTX_free(ctx);

    return result;
}

static char *get_aia_url(
    TLSRepair *repair,
    X509 *cert
)
{
    if(!cert){
        set_error(
            repair,
            "invalid certificate for AIA lookup"
        );

        return NULL;
    }

    AUTHORITY_INFO_ACCESS *aia =
        X509_get_ext_d2i(
            cert,
            NID_info_access,
            NULL,
            NULL
        );

    if(!aia){
        return NULL;
    }

    for(int i = 0;
        i < sk_ACCESS_DESCRIPTION_num(aia);
        i++){

        ACCESS_DESCRIPTION *ad =
            sk_ACCESS_DESCRIPTION_value(
                aia,
                i
            );

        if(!ad){
            continue;
        }

        if(OBJ_obj2nid(
            ad->method
        ) != NID_ad_ca_issuers){

            continue;
        }

        if(!ad->location){
            continue;
        }

        if(ad->location->type != GEN_URI){
            continue;
        }

        ASN1_IA5STRING *uri =
            ad->location->
                d.uniformResourceIdentifier;

        if(!uri){
            continue;
        }

        const unsigned char *data =
            ASN1_STRING_get0_data(uri);

        int length =
            ASN1_STRING_length(uri);

        if(!data || length <= 0){
            continue;
        }

        char *url =
            malloc(
                (size_t)length + 1
            );

        if(!url){

            set_error(
                repair,
                "failed to allocate AIA URL"
            );

            AUTHORITY_INFO_ACCESS_free(aia);

            return NULL;
        }

        memcpy(
            url,
            data,
            (size_t)length
        );

        url[length] = '\0';

        if(strncasecmp(url, "http://", 7) != 0 &&
           strncasecmp(url, "https://", 8) != 0){

                set_error(
                    repair,
                    "unsupported AIA URL scheme"
                );

                free(url);

                AUTHORITY_INFO_ACCESS_free(aia);

                return NULL;
            }

        AUTHORITY_INFO_ACCESS_free(aia);

        return url;
    }

    AUTHORITY_INFO_ACCESS_free(aia);

    return NULL;
}

static int certificate_matches_issuer(
    X509 *leaf,
    X509 *issuer
)
{
    if(!leaf || !issuer){
        return 0;
    }

    X509_NAME *leaf_issuer =
        X509_get_issuer_name(leaf);

    X509_NAME *issuer_subject =
        X509_get_subject_name(issuer);

    if(!leaf_issuer ||
       !issuer_subject){

        return 0;
    }

    if(X509_NAME_cmp(
        leaf_issuer,
        issuer_subject
    ) != 0){

        return 0;
    }

    EVP_PKEY *key =
        X509_get_pubkey(issuer);

    if(!key){
        return 0;
    }

    int result =
        X509_verify(
            leaf,
            key
        );

    EVP_PKEY_free(key);

    return result == 1;
}

static int stack_contains_certificate(
    STACK_OF(X509) *stack,
    X509 *cert
)
{
    if(!stack || !cert){
        return 0;
    }

    for(int i = 0;
        i < sk_X509_num(stack);
        i++){

        X509 *existing =
            sk_X509_value(
                stack,
                i
            );

        if(existing &&
           X509_cmp(
               existing,
               cert
           ) == 0){

            return 1;
        }
    }

    return 0;
}

static int add_certificate_to_untrusted(
    STACK_OF(X509) *untrusted,
    X509 *cert
)
{
    if(!untrusted || !cert){
        return 0;
    }

    if(stack_contains_certificate(
        untrusted,
        cert
    )){
        return 1;
    }

    if(X509_up_ref(cert) != 1){
        return 0;
    }

    if(!sk_X509_push(
        untrusted,
        cert
    )){

        X509_free(cert);

        return 0;
    }

    return 1;
}

static int add_certificate_to_repair(
    TLSRepair *repair,
    X509 *cert
)
{
    if(!repair || !cert){
        return 0;
    }

    if(!repair->aia_certificates){

        repair->aia_certificates =
            sk_X509_new_null();

        if(!repair->aia_certificates){
            set_error(
                repair,
                "failed to create AIA certificate stack"
            );

            return 0;
        }
    }

    if(stack_contains_certificate(
        repair->aia_certificates,
        cert
    )){
        return 1;
    }

    if(X509_up_ref(cert) != 1){
        set_error(
            repair,
            "failed to increase AIA certificate reference count"
        );

        if(sk_X509_num(
            repair->aia_certificates
        ) == 0){

            sk_X509_free(
                repair->aia_certificates
            );

            repair->aia_certificates = NULL;
        }

        return 0;
    }

    if(!sk_X509_push(
        repair->aia_certificates,
        cert
    )){

        set_error(
            repair,
            "failed to add certificate to AIA repair chain"
        );

        X509_free(cert);

        if(sk_X509_num(
            repair->aia_certificates
        ) == 0){

            sk_X509_free(
                repair->aia_certificates
            );

            repair->aia_certificates = NULL;
        }

        return 0;
    }

    return 1;
}

static int add_intermediates_to_verify_context(
    X509_STORE_CTX *ctx,
    STACK_OF(X509) *certificates
)
{
    if(!ctx || !certificates){
        return 0;
    }

    STACK_OF(X509) *untrusted =
        X509_STORE_CTX_get0_untrusted(ctx);

    if(!untrusted){
        return 0;
    }

    for(int i = 0;
        i < sk_X509_num(certificates);
        i++){

        X509 *cert =
            sk_X509_value(
                certificates,
                i
            );

        if(!cert){
            continue;
        }

        if(!add_certificate_to_untrusted(
            untrusted,
            cert
        )){
            return 0;
        }
    }

    return 1;
}

static int cert_verify_callback(
    X509_STORE_CTX *ctx,
    void *arg
)
{
    TLSRepair *repair = arg;

    if(!ctx){
        return 0;
    }

    if(repair &&
       repair->aia_certificates){

        if(!add_intermediates_to_verify_context(
            ctx,
            repair->aia_certificates
        )){

            set_error(
                repair,
                "failed to add AIA certificates to verification context"
            );

            return 0;
        }
    }

    int result =
        X509_verify_cert(ctx);

    if(result != 1){

        int error =
            X509_STORE_CTX_get_error(ctx);

        int depth =
            X509_STORE_CTX_get_error_depth(ctx);

        char msg[256];

        snprintf(
            msg,
            sizeof(msg),
            "certificate verification failed depth=%d error=%d (%s)",
            depth,
            error,
            X509_verify_cert_error_string(error)
        );

        if(repair){
            set_error(
                repair,
                msg
            );
        }

        return 0;
    }

    return 1;
}

static CURLcode ssl_ctx_callback(
    CURL *curl,
    void *sslctx,
    void *clientp
)
{
    (void)curl;

    SSL_CTX *ctx = sslctx;
    TLSRepair *repair = clientp;

    if(!ctx || !repair){
        return CURLE_OK;
    }

    if(!repair->aia_certificates ||
       sk_X509_num(
           repair->aia_certificates
       ) == 0){

        return CURLE_OK;
    }

    SSL_CTX_set_cert_verify_callback(
        ctx,
        cert_verify_callback,
        repair
    );

    return CURLE_OK;
}

static int configure_curl_with_intermediates(
    TLSRepair *repair
)
{
    if(!repair){
        return 0;
    }

    if(!repair->curl){
        set_error(
            repair,
            "CURL handle is unavailable"
        );

        return 0;
    }

    if(!repair->aia_certificates ||
       sk_X509_num(
           repair->aia_certificates
       ) == 0){

        set_error(
            repair,
            "AIA repair certificates are unavailable"
        );

        return 0;
    }

    CURLcode result;

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_CTX_FUNCTION,
            ssl_ctx_callback
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to configure SSL context",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_CTX_DATA,
            repair
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to configure SSL context data",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_VERIFYPEER,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to enable SSL certificate verification",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_VERIFYHOST,
            2L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_SSL_VERIFYHOST",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_FRESH_CONNECT,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_FRESH_CONNECT",
            result
        );

        return 0;
    }

    return 1;
}

static int reset_curl_for_final_request(
    TLSRepair *repair
)
{
    if(!repair ||
       !repair->curl){

        set_error(
            repair,
            "invalid TLSRepair handle"
        );

        return 0;
    }

    CURLcode result;

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_NOBODY,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_NOBODY",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_HTTPGET,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_HTTPGET",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_CUSTOMREQUEST,
            NULL
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_CUSTOMREQUEST",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_POST,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_POST",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_UPLOAD,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_UPLOAD",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_VERIFYPEER,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_SSL_VERIFYPEER",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_VERIFYHOST,
            2L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_SSL_VERIFYHOST",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_FRESH_CONNECT,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_FRESH_CONNECT",
            result
        );

        return 0;
    }

    return 1;
}

static int get_server_certificates(
    TLSRepair *repair,
    STACK_OF(X509) **certificates
)
{
    if(!repair){
        return 0;
    }

    if(!repair->curl ||
       !certificates){

        set_error(
            repair,
            "invalid server certificate discovery parameters"
        );

        return 0;
    }

    *certificates = NULL;

    CURLcode result;

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_NOBODY,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_NOBODY",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_HTTPGET,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_HTTPGET",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_CERTINFO,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_CERTINFO",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_VERIFYPEER,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to disable SSL certificate verification",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_VERIFYHOST,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to disable SSL hostname verification",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_FRESH_CONNECT,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_FRESH_CONNECT",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_WRITEFUNCTION,
            discard_callback
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_WRITEFUNCTION",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_WRITEDATA,
            NULL
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_WRITEDATA",
            result
        );

        return 0;
    }

    result =
        curl_easy_perform(
            repair->curl
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "server certificate discovery request failed",
            result
        );

        return 0;
    }

    if(!repair->url){

        const char *effective_url = NULL;

        result =
            curl_easy_getinfo(
                repair->curl,
                CURLINFO_EFFECTIVE_URL,
                &effective_url
            );

        if(result != CURLE_OK ||
           !effective_url){

            set_curl_error(
                repair,
                "failed to get original CURL URL",
                result
            );

            return 0;
        }

        repair->url =
            malloc(
                strlen(effective_url) + 1
            );

        if(!repair->url){

            set_error(
                repair,
                "failed to allocate original CURL URL"
            );

            return 0;
        }

        strcpy(
            repair->url,
            effective_url
        );
    }

    struct curl_certinfo *certInfo = NULL;

    result =
        curl_easy_getinfo(
            repair->curl,
            CURLINFO_CERTINFO,
            &certInfo
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to get CURLINFO_CERTINFO",
            result
        );

        return 0;
    }

    if(!certInfo){
        set_error(
            repair,
            "server certificate information is unavailable"
        );

        return 0;
    }

    *certificates =
        parse_certificates(
            repair,
            certInfo
        );

    if(!*certificates){
        return 0;
    }

    if(sk_X509_num(*certificates) == 0){

        set_error(
            repair,
            "server certificate chain is empty"
        );

        sk_X509_pop_free(
            *certificates,
            X509_free
        );

        *certificates = NULL;

        return 0;
    }

    return 1;
}

static int download_aia_certificate(
    TLSRepair *repair,
    CURL *curl,
    const char *url,
    struct Memory *memory
)
{
    if(!repair){
        return 0;
    }

    if(!curl || !url || !memory){
        set_error(
            repair,
            "invalid AIA download parameters"
        );

        return 0;
    }

    memset(
        memory,
        0,
        sizeof(*memory)
    );

    CURLcode result;

    const char *original_url =
        repair->url;

    if(!original_url){

        result =
            curl_easy_getinfo(
                curl,
                CURLINFO_EFFECTIVE_URL,
                &original_url
            );

        if(result != CURLE_OK ||
           !original_url){

            set_curl_error(
                repair,
                "failed to get original CURL URL",
                result
            );

            return 0;
        }
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_URL,
            url
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_URL",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_NOBODY,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_NOBODY",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_HTTPGET,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_HTTPGET",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_CUSTOMREQUEST,
            NULL
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_CUSTOMREQUEST",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_POST,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_POST",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_UPLOAD,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_UPLOAD",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_WRITEFUNCTION,
            write_callback
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_WRITEFUNCTION",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_WRITEDATA,
            memory
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_WRITEDATA",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_SSL_VERIFYPEER,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to disable SSL certificate verification",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_SSL_VERIFYHOST,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to disable SSL hostname verification",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_FRESH_CONNECT,
            1L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_FRESH_CONNECT",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_FOLLOWLOCATION,
            0L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_FOLLOWLOCATION",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_CONNECTTIMEOUT,
            10L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_CONNECTTIMEOUT",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_TIMEOUT,
            30L
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to set CURLOPT_TIMEOUT",
            result
        );

        goto restore_url;
    }

    result =
        curl_easy_perform(curl);

    if(result != CURLE_OK){

        set_curl_error(
            repair,
            "AIA certificate download failed",
            result
        );

        free(memory->data);

        memory->data = NULL;
        memory->size = 0;

        goto restore_url;
    }

    if(!memory->data ||
       memory->size == 0){

        set_error(
            repair,
            "AIA certificate download returned empty data"
        );

        free(memory->data);

        memory->data = NULL;
        memory->size = 0;

        goto restore_url;
    }


restore_url:

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_URL,
            original_url
        );

    if(result != CURLE_OK){

        set_curl_error(
            repair,
            "failed to restore original CURLOPT_URL",
            result
        );

        free(memory->data);

        memory->data = NULL;
        memory->size = 0;

        return 0;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_WRITEFUNCTION,
            discard_callback
        );

    if(result != CURLE_OK){

        set_curl_error(
            repair,
            "failed to restore CURLOPT_WRITEFUNCTION",
            result
        );

        free(memory->data);

        memory->data = NULL;
        memory->size = 0;

        return 0;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_WRITEDATA,
            NULL
        );

    if(result != CURLE_OK){

        set_curl_error(
            repair,
            "failed to restore CURLOPT_WRITEDATA",
            result
        );

        free(memory->data);

        memory->data = NULL;
        memory->size = 0;

        return 0;
    }

    if(!memory->data ||
       memory->size == 0){

        return 0;
    }

    return 1;
}

static X509 *download_and_parse_aia_certificate(
    TLSRepair *repair,
    CURL *curl,
    const char *url
)
{
    struct Memory memory = {0};

    if(!download_aia_certificate(
        repair,
        curl,
        url,
        &memory
    )){
        return NULL;
    }

    X509 *cert =
        parse_certificate_memory(
            repair,
            memory.data,
            memory.size
        );

    free(memory.data);

    if(!cert){
        return NULL;
    }

    return cert;
}

int tlsrepair_global_init(void)
{
    return curl_global_init(
        CURL_GLOBAL_DEFAULT
    ) == CURLE_OK;
}

void tlsrepair_global_cleanup(void)
{
    curl_global_cleanup();
}

TLSRepair *tlsrepair_create(
    const char *url
)
{
    if(!url){
        return NULL;
    }

    TLSRepair *repair =
        calloc(
            1,
            sizeof(*repair)
        );

    if(!repair){
        return NULL;
    }

    repair->curl =
        curl_easy_init();

    if(!repair->curl){
        free(repair);
        return NULL;
    }

    repair->owns_curl = 1;

    repair->url =
        malloc(
            strlen(url) + 1
        );

    if(!repair->url){

        curl_easy_cleanup(
            repair->curl
        );

        free(repair);

        return NULL;
    }

    strcpy(
        repair->url,
        url
    );

    CURLcode result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_URL,
            repair->url
        );

    if(result != CURLE_OK){

        curl_easy_cleanup(
            repair->curl
        );

        free(repair->url);
        free(repair);

        return NULL;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_CONNECTTIMEOUT,
            10L
        );

    if(result != CURLE_OK){

        curl_easy_cleanup(
            repair->curl
        );

        free(repair->url);
        free(repair);

        return NULL;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_TIMEOUT,
            60L
        );

    if(result != CURLE_OK){

        curl_easy_cleanup(
            repair->curl
        );

        free(repair->url);
        free(repair);

        return NULL;
    }

    return repair;
}

TLSRepair *tlsrepair_from_curl(
    CURL *curl
)
{
    if(!curl){
        return NULL;
    }

    TLSRepair *repair =
        calloc(
            1,
            sizeof(*repair)
        );

    if(!repair){
        return NULL;
    }

    repair->curl = curl;
    repair->owns_curl = 0;

    CURLcode result;

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_CONNECTTIMEOUT,
            10L
        );

    if(result != CURLE_OK){
        free(repair);
        return NULL;
    }

    result =
        curl_easy_setopt(
            curl,
            CURLOPT_TIMEOUT,
            60L
        );

    if(result != CURLE_OK){
        free(repair);
        return NULL;
    }

    return repair;
}

int tlsrepair_set_proxy(
    TLSRepair *repair,
    const char *proxy
)
{
    if(!repair){
        return 0;
    }

    if(!repair->curl){
        set_error(
            repair,
            "CURL handle is unavailable"
        );

        return 0;
    }

    free(repair->proxy);

    repair->proxy = NULL;

    if(!proxy){

        CURLcode result =
            curl_easy_setopt(
                repair->curl,
                CURLOPT_PROXY,
                NULL
            );

        if(result != CURLE_OK){
            set_curl_error(
                repair,
                "failed to clear CURLOPT_PROXY",
                result
            );

            return 0;
        }

        return 1;
    }

    repair->proxy =
        malloc(
            strlen(proxy) + 1
        );

    if(!repair->proxy){
        set_error(
            repair,
            "failed to allocate proxy string"
        );

        return 0;
    }

    strcpy(
        repair->proxy,
        proxy
    );

    CURLcode result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_PROXY,
            repair->proxy
        );

    if(result != CURLE_OK){

        set_curl_error(
            repair,
            "failed to set CURLOPT_PROXY",
            result
        );

        free(repair->proxy);

        repair->proxy = NULL;

        return 0;
    }

    return 1;
}

int tlsrepair_prepare(
    TLSRepair *repair
)
{
    if(!repair){
        return 0;
    }

    set_error(
        repair,
        NULL
    );

    if(!repair->curl){

        set_error(
            repair,
            "invalid TLSRepair handle or URL"
        );

        return 0;
    }

    repair->repaired = 0;

    if(repair->aia_certificates){

        sk_X509_pop_free(
            repair->aia_certificates,
            X509_free
        );

        repair->aia_certificates = NULL;
    }

    CURLcode result;

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_CTX_FUNCTION,
            NULL
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to clear SSL context callback",
            result
        );

        return 0;
    }

    result =
        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_CTX_DATA,
            NULL
        );

    if(result != CURLE_OK){
        set_curl_error(
            repair,
            "failed to clear SSL context callback data",
            result
        );

        return 0;
    }

    STACK_OF(X509) *certificates = NULL;

    if(!get_server_certificates(
        repair,
        &certificates
    )){
        return 0;
    }

    X509 *leaf =
        sk_X509_value(
            certificates,
            0
        );

    if(!leaf){

        set_error(
            repair,
            "server certificate chain does not contain a leaf certificate"
        );

        sk_X509_pop_free(
            certificates,
            X509_free
        );

        return 0;
    }

    X509_STORE *store =
        create_trust_store(repair);

    if(!store){

        sk_X509_pop_free(
            certificates,
            X509_free
        );

        return 0;
    }

    STACK_OF(X509) *untrusted =
        create_untrusted_stack(
            repair,
            certificates
        );

    if(!untrusted){

        X509_STORE_free(store);

        sk_X509_pop_free(
            certificates,
            X509_free
        );

        return 0;
    }

    int verifyResult =
        verify_certificate_chain(
            repair,
            leaf,
            store,
            untrusted
        );

    if(verifyResult == 1){

        sk_X509_pop_free(
            untrusted,
            X509_free
        );

        X509_STORE_free(store);

        sk_X509_pop_free(
            certificates,
            X509_free
        );

        return reset_curl_for_final_request(
            repair
        );
    }


    if(verifyResult < 0){

        sk_X509_pop_free(
            untrusted,
            X509_free
        );

        X509_STORE_free(store);

        sk_X509_pop_free(
            certificates,
            X509_free
        );

        return 0;
    }

    X509 *current = X509_dup(leaf);

    if(!current){

        set_error(
            repair,
            "failed to duplicate leaf certificate"
        );

        X509_free(current);
        current = NULL;

        sk_X509_pop_free(
            untrusted,
            X509_free
        );

        X509_STORE_free(store);

        sk_X509_pop_free(
            certificates,
            X509_free
        );

        return 0;
    }
    

    int repaired = 0;

    for(int depth = 0;
        depth < TLSREPAIR_MAX_AIA_DEPTH;
        depth++){

        char *aiaUrl =
            get_aia_url(
                repair,
                current
            );

        if(!aiaUrl){

            if(!repair->error){

                char error_message[256];

                snprintf(
                    error_message,
                    sizeof(error_message),
                    "no AIA issuer URL available at certificate depth %d",
                    depth
                );

                set_error(
                    repair,
                    error_message
                );
            }

            break;
        }

        X509 *aiaCert =
            download_and_parse_aia_certificate(
                repair,
                repair->curl,
                aiaUrl
            );

        free(aiaUrl);

        if(!aiaCert){
            break;
        }

        if(!certificate_matches_issuer(
            current,
            aiaCert
        )){

            set_error(
                repair,
                "AIA certificate is not the issuer of the current certificate"
            );

            X509_free(aiaCert);

            break;
        }

        if(stack_contains_certificate(
            untrusted,
            aiaCert
        )){

            X509_free(aiaCert);

            break;
        }

        if(!sk_X509_push(
            untrusted,
            aiaCert
        )){

            set_error(
                repair,
                "failed to add AIA certificate to verification chain"
            );

            X509_free(aiaCert);

            break;
        }

        if(!add_certificate_to_repair(
            repair,
            aiaCert
        )){

            sk_X509_pop(untrusted);
            X509_free(aiaCert);

            break;
        }

        int result =
            verify_certificate_chain(
                repair,
                leaf,
                store,
                untrusted
            );

        if(result == 1){

            repaired = 1;

            set_error(
                repair,
                NULL
            );

            sk_X509_pop(
                untrusted
            );

            X509_free(aiaCert);

            break;
        }

        if(result < 0){
            sk_X509_pop(untrusted);
            X509_free(aiaCert);
            break;
        }

        X509 *next = X509_dup(aiaCert);

        if(!next){

            set_error(
                repair,
                "failed to duplicate AIA issuer certificate"
            );

            X509_free(aiaCert);

            break;
        }


        X509_free(current);

        current = next;
    }

    X509_free(current);
    
    sk_X509_pop_free(
        untrusted,
        X509_free
    );
    X509_STORE_free(store);
    sk_X509_pop_free(
        certificates,
        X509_free
    );

    if(!repaired){

        if(repair->aia_certificates){

            sk_X509_pop_free(
                repair->aia_certificates,
                X509_free
            );

            repair->aia_certificates = NULL;
        }

        if(!repair->error){

            set_error(
                repair,
                "failed to repair certificate chain"
            );
        }

        return 0;
    }

    if(!configure_curl_with_intermediates(
        repair
    )){

        sk_X509_pop_free(
            repair->aia_certificates,
            X509_free
        );

        repair->aia_certificates = NULL;

        return 0;
    }

    if(!reset_curl_for_final_request(
        repair
    )){

        repair->repaired = 0;

        return 0;
    }

    repair->repaired = 1;

    return 1;
}

CURL *tlsrepair_curl(
    TLSRepair *repair
)
{
    if(!repair){
        return NULL;
    }

    return repair->curl;
}

void tlsrepair_destroy(
    TLSRepair *repair
)
{
    if(!repair){
        return;
    }

    if(repair->curl){

        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_CTX_FUNCTION,
            NULL
        );

        curl_easy_setopt(
            repair->curl,
            CURLOPT_SSL_CTX_DATA,
            NULL
        );
    }

    if(repair->curl &&
       repair->owns_curl){

        curl_easy_cleanup(
            repair->curl
        );
    }

    if(repair->aia_certificates){

        sk_X509_pop_free(
            repair->aia_certificates,
            X509_free
        );
    }

    free(repair->error);
    free(repair->proxy);
    free(repair->url);
    free(repair);
}