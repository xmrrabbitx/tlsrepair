#ifndef TLSREPAIR_H
#define TLSREPAIR_H

#include <curl/curl.h>

typedef struct TLSRepair TLSRepair;

int tlsrepair_global_init(void);

void tlsrepair_global_cleanup(void);

TLSRepair *tlsrepair_create(
    const char *url
);

TLSRepair *tlsrepair_from_curl(
    CURL *curl
);

int tlsrepair_set_proxy(
    TLSRepair *repair,
    const char *proxy
);

int tlsrepair_prepare(
    TLSRepair *repair
);

CURL *tlsrepair_curl(
    TLSRepair *repair
);

void tlsrepair_destroy(
    TLSRepair *repair
);

const char *tlsrepair_error(
    TLSRepair *repair
);

#endif