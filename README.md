# tlsrepair

`tlsrepair` is a C library for repairing **incomplete TLS certificate chains** using the **Authority Information Access (AIA)** extension.

It is designed for applications using **libcurl** and **OpenSSL** where a remote server does not provide all required intermediate certificates.

Instead of disabling TLS verification for the final connection, `tlsrepair` discovers missing intermediate certificates through AIA, downloads them, verifies their issuer relationships, verifies the resulting certificate path against the system trust store, and provides the discovered intermediates to OpenSSL during the final TLS verification.

## Features

* Detects incomplete TLS certificate chains
* Reads AIA `caIssuers` extensions
* Downloads missing intermediate certificates
* Supports multiple intermediate certificates
* Cryptographically verifies downloaded certificates before using them
* Uses the system OpenSSL trust store
* Keeps TLS peer verification enabled for the final request
* Keeps hostname verification enabled
* Works with libcurl
* Supports HTTP proxies
* Provides both static and shared libraries
* CMake package support

## How It Works

When a server provides an incomplete certificate chain, `tlsrepair` first obtains the certificates provided by the server and attempts normal certificate verification.

If verification fails because an intermediate certificate is missing, the library follows the AIA `caIssuers` information in the current certificate.

```text
Server
  │
  │  Incomplete certificate chain
  ▼
Server certificates
  │
  ▼
Verify against system trust store
  │
  │  Missing intermediate
  ▼
AIA caIssuers URL
  │
  ▼
Download issuer certificate
  │
  ▼
Verify issuer relationship
  │
  ▼
Add intermediate to verification chain
  │
  ▼
Verify against system trust store
  │
  ├── Missing another intermediate
  │        │
  │        └── Repeat AIA process
  │
  ▼
Chain verification succeeds
  │
  ▼
Configure OpenSSL/libcurl
  │
  ▼
Final HTTPS request
```

The important distinction is that `tlsrepair` does **not** modify the certificate chain sent by the server.

Instead, the missing intermediate certificates discovered through AIA are made available to OpenSSL as additional certificates during TLS certificate verification.

Conceptually:

```text
Server sends:

    Server Certificate
           │
           ▼
    [Missing Intermediate]
           │
           ▼
       Root CA


tlsrepair provides:

    Server Certificate
           │
           ▼
    AIA Intermediate
           │
           ▼
       Root CA
           │
           ▼
    System Trust Store
```

The final TLS connection still performs normal certificate and hostname verification.

## Requirements

* C11
* CMake 3.16 or newer
* libcurl
* OpenSSL

## Installation

Clone the repository:

```bash
git clone https://github.com/xmrrabbitx/tlsrepair.git
cd tlsrepair
```

Configure the project:

```bash
cmake -S . -B build
```

Build:

```bash
cmake --build build
```

Install:

```bash
sudo cmake --install build
```

The default installation installs the library and headers under `/usr/local`.

## Using tlsrepair with CMake

After installation, use `find_package()` in your project CMakeLists.txt:

```cmake
cmake_minimum_required(VERSION 3.16)

project(myapp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(tlsrepair REQUIRED)

add_executable(myapp
    src/main.c
)

target_link_libraries(
    myapp
    PRIVATE
        tlsrepair::tlsrepair
)
```

Then include the public header:

```c
#include <tlsrepair/tlsrepair.h>
```

## Basic Usage

`tlsrepair` supports two ways of working with libcurl:

1. **Create mode** — `tlsrepair` creates and owns the CURL handle.
2. **Existing CURL mode** — the application creates the CURL handle and passes it to `tlsrepair` using `tlsrepair_from_curl()`.

Both modes use the same CURL handle for certificate discovery, AIA retrieval, TLS repair, and the final HTTP request.

### Create Mode

In create mode, `tlsrepair` creates and owns the CURL handle.

```c
#include <stdio.h>
#include <curl/curl.h>
#include <tlsrepair/tlsrepair.h>

static size_t write_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    (void)userp;

    return fwrite(
        contents,
        size,
        nmemb,
        stdout
    );
}

int main(void)
{
    if(!tlsrepair_global_init()){
        return 1;
    }

    TLSRepair *repair =
        tlsrepair_create(
            "https://example.com"
        );

    if(!repair){
        tlsrepair_global_cleanup();
        return 1;
    }

    if(!tlsrepair_prepare(repair)){
        fprintf(
            stderr,
            "TLSRepair error: %s\n",
            tlsrepair_error(repair)
                ? tlsrepair_error(repair)
                : "unknown error"
        );

        tlsrepair_destroy(repair);
        tlsrepair_global_cleanup();

        return 1;
    }

    CURL *curl =
        tlsrepair_curl(repair);

    if(!curl){
        tlsrepair_destroy(repair);
        tlsrepair_global_cleanup();

        return 1;
    }

    /*
     * Configure the application's response handling.
     */
    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    CURLcode result =
        curl_easy_perform(curl);

    if(result != CURLE_OK){
        fprintf(
            stderr,
            "curl error: %s\n",
            curl_easy_strerror(result)
        );
    }

    tlsrepair_destroy(repair);
    tlsrepair_global_cleanup();

    return result == CURLE_OK ? 0 : 1;
}
```

In this mode:

```text
tlsrepair_create()
        │
        ▼
   TLSRepair
        │
        ▼
   CURL handle
        │
        ├── owned by TLSRepair
        │
        ▼
tlsrepair_prepare()
        │
        ▼
tlsrepair_curl()
        │
        ▼
curl_easy_perform()
        │
        ▼
tlsrepair_destroy()
        │
        ▼
CURL handle is cleaned up
```

The application must **not** call `curl_easy_cleanup()` on the CURL handle returned by `tlsrepair_curl()`.

---

### Existing CURL Mode

Applications that already create and configure their own libcurl handle can pass that handle to `tlsrepair` using `tlsrepair_from_curl()`.

This allows `tlsrepair` to operate on an existing CURL handle instead of creating a new one.

```c
TLSRepair *tlsrepair_from_curl(
    CURL *curl
);
```

Example:

```c
#include <stdio.h>
#include <curl/curl.h>
#include <tlsrepair/tlsrepair.h>

static size_t write_callback(
    void *contents,
    size_t size,
    size_t nmemb,
    void *userp
)
{
    (void)userp;

    return fwrite(
        contents,
        size,
        nmemb,
        stdout
    );
}

int main(void)
{
    if(!tlsrepair_global_init()){
        return 1;
    }

    /*
     * The application creates the CURL handle.
     */
    CURL *curl =
        curl_easy_init();

    if(!curl){
        tlsrepair_global_cleanup();
        return 1;
    }

    curl_easy_setopt(
        curl,
        CURLOPT_URL,
        "https://example.com"
    );

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    /*
     * Give the existing CURL handle to TLSRepair.
     */
    TLSRepair *repair =
        tlsrepair_from_curl(
            curl
        );

    if(!repair){
        curl_easy_cleanup(curl);
        tlsrepair_global_cleanup();

        return 1;
    }

    if(!tlsrepair_prepare(repair)){
        fprintf(
            stderr,
            "TLSRepair error: %s\n",
            tlsrepair_error(repair)
                ? tlsrepair_error(repair)
                : "unknown error"
        );

        tlsrepair_destroy(repair);
        curl_easy_cleanup(curl);
        tlsrepair_global_cleanup();

        return 1;
    }

    /*
     * tlsrepair_curl() returns the same CURL
     * handle that was passed to tlsrepair_from_curl().
     */
    curl =
        tlsrepair_curl(repair);

    if(!curl){
        tlsrepair_destroy(repair);
        curl_easy_cleanup(curl);
        tlsrepair_global_cleanup();

        return 1;
    }

    /*
     * Configure the application's final response handling.
     */
    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        write_callback
    );

    CURLcode result =
        curl_easy_perform(curl);

    if(result != CURLE_OK){
        fprintf(
            stderr,
            "curl error: %s\n",
            curl_easy_strerror(result)
        );
    }

    /*
     * TLSRepair does not own the CURL handle
     * in from_curl() mode.
     */
    tlsrepair_destroy(repair);

    /*
     * The application is responsible for cleanup.
     */
    curl_easy_cleanup(curl);

    tlsrepair_global_cleanup();

    return result == CURLE_OK ? 0 : 1;
}
```

The ownership model is different:

```text
Application
    │
    ▼
curl_easy_init()
    │
    ▼
CURL handle
    │
    │ owned by application
    ▼
tlsrepair_from_curl(curl)
    │
    ▼
TLSRepair
    │
    ▼
tlsrepair_prepare()
    │
    ▼
tlsrepair_curl()
    │
    │ returns the same CURL handle
    ▼
curl_easy_perform()
    │
    ▼
tlsrepair_destroy()
    │
    │ does NOT clean up CURL
    ▼
curl_easy_cleanup()
    │
    │ application performs cleanup
    ▼
CURL destroyed
```

The important rule is:

```text
tlsrepair_create()
    → TLSRepair owns CURL
    → tlsrepair_destroy() cleans CURL

tlsrepair_from_curl()
    → Application owns CURL
    → tlsrepair_destroy() does NOT clean CURL
    → Application calls curl_easy_cleanup()
```

## API

### `tlsrepair_global_init`

Initializes the global libcurl state.

```c
int tlsrepair_global_init(void);
```

Returns:

```text
1  Success
0  Failure
```

Call this before creating `TLSRepair` objects.

---

### `tlsrepair_global_cleanup`

Cleans up the global libcurl state.

```c
void tlsrepair_global_cleanup(void);
```

Call this after all `TLSRepair` objects have been destroyed.

---

### `tlsrepair_create`

Creates a TLS repair object and its internal CURL handle.

```c
TLSRepair *tlsrepair_create(
    const char *url
);
```

The URL is used during certificate discovery and repair.

The CURL handle is owned by the resulting `TLSRepair` object.

Returns `NULL` on failure.

---

### `tlsrepair_from_curl`

Creates a TLS repair object from an existing libcurl easy handle.

```c
TLSRepair *tlsrepair_from_curl(
    CURL *curl
);
```

The supplied CURL handle must already have the request URL configured.

Example:

```c
CURL *curl =
    curl_easy_init();

curl_easy_setopt(
    curl,
    CURLOPT_URL,
    "https://example.com"
);

TLSRepair *repair =
    tlsrepair_from_curl(curl);
```

`tlsrepair_from_curl()` does **not** take ownership of the CURL handle.

The application remains responsible for calling:

```c
curl_easy_cleanup(curl);
```

after:

```c
tlsrepair_destroy(repair);
```

The same CURL handle is used throughout the repair process.

This mode is useful when the application already has a CURL handle with its own request configuration.

---

### `tlsrepair_set_proxy`

Configures a proxy for the CURL connection.

```c
int tlsrepair_set_proxy(
    TLSRepair *repair,
    const char *proxy
);
```

Example:

```c
tlsrepair_set_proxy(
    repair,
    "http://127.0.0.1:8080"
);
```

Pass `NULL` to remove the configured proxy.

Returns:

```text
1  Success
0  Failure
```

---

### `tlsrepair_prepare`

Inspects and repairs the TLS certificate chain.

```c
int tlsrepair_prepare(
    TLSRepair *repair
);
```

Returns:

```text
1  Success
0  Failure
```

A successful result means the CURL connection has been prepared for the application's final HTTPS request.

---

### `tlsrepair_curl`

Returns the CURL easy handle associated with the repair object.

```c
CURL *tlsrepair_curl(
    TLSRepair *repair
);
```

In `tlsrepair_create()` mode, this returns the CURL handle created by TLSRepair.

In `tlsrepair_from_curl()` mode, this returns the **same CURL handle supplied by the application**.

Example:

```c
CURL *curl =
    tlsrepair_curl(repair);
```

The application uses this handle for the final HTTP request:

```c
curl_easy_setopt(
    curl,
    CURLOPT_WRITEFUNCTION,
    write_callback
);

curl_easy_perform(curl);
```

---

### `tlsrepair_destroy`

Destroys a TLS repair object and releases its resources.

```c
void tlsrepair_destroy(
    TLSRepair *repair
);
```

Ownership determines whether the CURL handle is cleaned up.

For `tlsrepair_create()`:

```text
tlsrepair_destroy()
    └── cleans up CURL
```

For `tlsrepair_from_curl()`:

```text
tlsrepair_destroy()
    └── does NOT clean up CURL

application
    └── curl_easy_cleanup(curl)
```

---

## Request Ownership

`tlsrepair` handles **TLS certificate discovery and repair**, not the application's HTTP logic.

The application remains responsible for:

* HTTP method
* Request headers
* Request body
* Cookies
* Response callback
* Response processing
* HTTP status handling
* `curl_easy_perform()`

The general flow is:

```text
Application
    │
    ├── Create or provide CURL
    │
    ├── Create TLSRepair
    │
    ├── Configure proxy (optional)
    │
    ├── tlsrepair_prepare()
    │
    ├── tlsrepair_curl()
    │
    ├── Configure HTTP request
    │
    ├── Configure response handling
    │
    └── curl_easy_perform()
             │
             ▼
        HTTPS connection
             │
             ▼
     TLS certificate verification
             │
             ▼
       AIA intermediates
```

### Important: Response Callback

During certificate discovery, `tlsrepair` temporarily uses its own response handling internally.

Therefore, applications should configure their final response callback after `tlsrepair_prepare()` and before the final `curl_easy_perform()`.

For example:

```c
CURL *curl =
    tlsrepair_curl(repair);

curl_easy_setopt(
    curl,
    CURLOPT_WRITEFUNCTION,
    write_callback
);

curl_easy_perform(curl);
```

This keeps TLS certificate discovery separate from the application's final response processing.

## TLS Verification

During certificate discovery and AIA certificate retrieval, the library temporarily disables TLS certificate verification.

This is necessary because the server may initially provide an incomplete certificate chain, and the AIA certificate itself may need to be retrieved before normal verification can succeed.

The downloaded AIA certificate is **not trusted merely because it was downloaded**.

Before it is used, `tlsrepair` verifies the issuer relationship cryptographically. The resulting certificate path is then verified against the system trust store.

The final HTTPS request is performed with normal TLS verification enabled:

```text
CURLOPT_SSL_VERIFYPEER = 1
CURLOPT_SSL_VERIFYHOST = 2
```

The discovered intermediate certificates are supplied to OpenSSL during certificate verification.

Therefore, the library does **not** solve an incomplete certificate chain by permanently disabling TLS verification.

## Static and Shared Libraries

The project builds both:

```text
libtlsrepair.a
libtlsrepair.so
```

The shared library can be used through:

```cmake
target_link_libraries(
    myapp
    PRIVATE
        tlsrepair::tlsrepair
)
```

The static library is available through:

```cmake
target_link_libraries(
    myapp
    PRIVATE
        tlsrepair::tlsrepair_static
)
```

## Limitations

`tlsrepair` currently focuses on repairing missing intermediate certificates using AIA.

It does not:

* Disable TLS verification for the final request
* Replace an invalid or expired server certificate
* Replace an untrusted root certificate
* Ignore hostname verification
* Modify the system CA store
* Modify the certificate chain sent by the server
* Act as a general-purpose HTTP client

A server must provide usable AIA information for certificates that need to be discovered automatically.

The AIA URL must use a supported HTTP or HTTPS scheme.

## Thread Safety

A `TLSRepair` object should not be used concurrently from multiple threads.

Separate `TLSRepair` objects can be used by separate threads.

```text
Thread 1 → TLSRepair A
Thread 2 → TLSRepair B
Thread 3 → TLSRepair C
```

Do not share the same repair object between concurrent operations.

## Testing

The project includes test executables.

Build the project:

```bash
cmake -S . -B build
cmake --build build
```

Run the tests:

```bash
./build/tlsrepair_test_static
```

or:

```bash
./build/tlsrepair_test_shared
```

## License

This project is licensed under the MIT License.