#include <stdio.h>
#include <curl/curl.h>

#include "tlsrepair.h"

static size_t discard_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    (void)contents;
    (void)userp;

    return size * nmemb;
}

static int regular_request(void)
{
    CURL *curl;
    CURLcode result;
    long response_code = 0;

    curl = curl_easy_init();

    if(!curl){
        return 1;
    }

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        "https://incomplete-chain.badssl.com"
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        discard_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPGET,
        1L
    );

    result = curl_easy_perform(curl);

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        &response_code
    );

    printf(
        "Regular request: %s, HTTP %ld\n",
        curl_easy_strerror(result),
        response_code
    );

    curl_easy_cleanup(curl);

    return result == CURLE_OK ? 0 : 1;
}

static int repaired_request(void)
{
    TLSRepair *repair;
    CURL *curl;
    CURLcode result;
    long response_code = 0;

    repair = tlsrepair_create(
        "https://incomplete-chain.badssl.com"
    );

    if(!repair){
        return 1;
    }

    if(!tlsrepair_prepare(repair)){
        tlsrepair_destroy(repair);
        return 1;
    }

    curl = tlsrepair_curl(repair);

    if(!curl){
        tlsrepair_destroy(repair);
        return 1;
    }

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        "https://incomplete-chain.badssl.com"
    );

        curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        discard_callback
    );

    curl_easy_setopt(
        curl,
        CURLOPT_HTTPGET,
        1L
    );

    result = curl_easy_perform(curl);

    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        &response_code
    );

    printf(
        "Repaired request: %s, HTTP %ld\n",
        curl_easy_strerror(result),
        response_code
    );

    tlsrepair_destroy(repair);

    return result == CURLE_OK ? 0 : 1;
}

int main(void)
{
    int regular_result;
    int repaired_result;

    if(!tlsrepair_global_init()){
        return 1;
    }

    regular_result = regular_request();

    repaired_result = repaired_request();

    tlsrepair_global_cleanup();

    printf(
        "\nRegular: %s\n",
        regular_result == 0 ? "SUCCESS" : "FAILED"
    );

    printf(
        "Repaired: %s\n",
        repaired_result == 0 ? "SUCCESS" : "FAILED"
    );

    return repaired_result;
}

