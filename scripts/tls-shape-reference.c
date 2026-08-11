// Minimal libssl TLS 1.3 reference server for benchmark-tls-shape.sh.
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct alpn_config {
    unsigned char wire[256];
    unsigned int length;
};

static void print_json_string(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    putchar('"');
    while (*cursor != '\0') {
        switch (*cursor) {
        case '"':
            fputs("\\\"", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        case '\b':
            fputs("\\b", stdout);
            break;
        case '\f':
            fputs("\\f", stdout);
            break;
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\r':
            fputs("\\r", stdout);
            break;
        case '\t':
            fputs("\\t", stdout);
            break;
        default:
            if (*cursor < 0x20) {
                fprintf(stdout, "\\u%04x", *cursor);
            } else {
                putchar(*cursor);
            }
        }
        cursor++;
    }
    putchar('"');
}

static void print_self_identity(void) {
    fputs("{\n  \"schemaVersion\": 1,\n  \"compiler\": ", stdout);
    print_json_string(__VERSION__);
    fputs(",\n  \"opensslCompileVersion\": ", stdout);
    print_json_string(OPENSSL_VERSION_TEXT);
    fprintf(stdout,
            ",\n  \"opensslCompileVersionNumber\": \"0x%lx\",\n  "
            "\"opensslRuntimeVersion\": ",
            (unsigned long)OPENSSL_VERSION_NUMBER);
    print_json_string(OpenSSL_version(OPENSSL_VERSION));
    fprintf(stdout,
            ",\n  \"opensslRuntimeVersionNumber\": \"0x%lx\",\n  "
            "\"opensslRuntimeBuiltOn\": ",
            OpenSSL_version_num());
    print_json_string(OpenSSL_version(OPENSSL_BUILT_ON));
    fputs(",\n  \"opensslRuntimePlatform\": ", stdout);
    print_json_string(OpenSSL_version(OPENSSL_PLATFORM));
    fputs(",\n  \"opensslRuntimeDirectory\": ", stdout);
    print_json_string(OpenSSL_version(OPENSSL_DIR));
    fputs(",\n  \"opensslRuntimeEnginesDirectory\": ", stdout);
    print_json_string(OpenSSL_version(OPENSSL_ENGINES_DIR));
    fputs(",\n  \"opensslRuntimeModulesDirectory\": ", stdout);
    print_json_string(OpenSSL_version(OPENSSL_MODULES_DIR));
    fputs(",\n  \"configPolicy\": \"OPENSSL_INIT_NO_LOAD_CONFIG\",\n  "
          "\"providerPolicy\": [\"default\"]\n}\n",
          stdout);
}

static int select_alpn(SSL *ssl, const unsigned char **out,
                       unsigned char *out_len, const unsigned char *client,
                       unsigned int client_len, void *argument) {
    struct alpn_config *config = argument;
    (void)ssl;
    if (config->length == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    if (SSL_select_next_proto((unsigned char **)out, out_len, config->wire,
                              config->length, client, client_len) !=
        OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

static size_t record_padding(SSL *ssl, int type, size_t length, void *argument) {
    const size_t *padding = argument;
    (void)ssl;
    (void)type;
    (void)length;
    return *padding;
}

static void fail_openssl(const char *operation) {
    fprintf(stderr, "%s failed\n", operation);
    ERR_print_errors_fp(stderr);
    exit(1);
}

static unsigned long parse_ulong(const char *text, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, text);
        exit(2);
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--identity") == 0) {
        print_self_identity();
        return 0;
    }
    if (argc != 12) {
        fprintf(stderr,
                "usage: %s PORT CERT KEY CIPHERSUITES GROUPS ALPN "
                "MIDDLEBOX MAX_FRAGMENT SPLIT_FRAGMENT PADDING TCP_NODELAY\n"
                "       %s --identity\n",
                argv[0],
                argv[0]);
        return 2;
    }

    const unsigned long port_value = parse_ulong(argv[1], "port");
    const unsigned long middlebox = parse_ulong(argv[7], "middlebox");
    const unsigned long max_fragment = parse_ulong(argv[8], "max fragment");
    const unsigned long split_fragment = parse_ulong(argv[9], "split fragment");
    const size_t padding = (size_t)parse_ulong(argv[10], "padding");
    const int tcp_nodelay = parse_ulong(argv[11], "TCP_NODELAY") != 0;
    if (port_value == 0 || port_value > 65535 || middlebox > 1 ||
        max_fragment > 16384 || split_fragment > 16384 || padding > 16384) {
        fprintf(stderr, "argument outside fixed bounds\n");
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                             OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                             OPENSSL_INIT_NO_LOAD_CONFIG,
                         NULL) != 1) {
        fail_openssl("OPENSSL_init_ssl");
    }
    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        fail_openssl("OSSL_PROVIDER_load(default)");
    }
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) {
        fail_openssl("SSL_CTX_new");
    }
    if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(context, argv[4]) != 1 ||
        SSL_CTX_set1_groups_list(context, argv[5]) != 1 ||
        SSL_CTX_use_certificate_chain_file(context, argv[2]) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, argv[3], SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        fail_openssl("SSL_CTX configuration");
    }
    SSL_CTX_set_num_tickets(context, 0);
    if (middlebox != 0) {
        SSL_CTX_set_options(context, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    } else {
        SSL_CTX_clear_options(context, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
    }
    if (max_fragment != 0 &&
        SSL_CTX_set_max_send_fragment(context, max_fragment) != 1) {
        fail_openssl("SSL_CTX_set_max_send_fragment");
    }
    if (split_fragment != 0 &&
        SSL_CTX_set_split_send_fragment(context, split_fragment) != 1) {
        fail_openssl("SSL_CTX_set_split_send_fragment");
    }
    if (padding != 0) {
        SSL_CTX_set_record_padding_callback(context, record_padding);
        SSL_CTX_set_record_padding_callback_arg(context, (void *)&padding);
    }

    struct alpn_config alpn = {{0}, 0};
    const size_t alpn_length = strlen(argv[6]);
    if (alpn_length > 255) {
        fprintf(stderr, "ALPN is too long\n");
        return 2;
    }
    if (alpn_length != 0) {
        alpn.wire[0] = (unsigned char)alpn_length;
        memcpy(alpn.wire + 1, argv[6], alpn_length);
        alpn.length = (unsigned int)alpn_length + 1;
        SSL_CTX_set_alpn_select_cb(context, select_alpn, &alpn);
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        return 1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((unsigned short)port_value);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 16) != 0) {
        perror("bind/listen");
        return 1;
    }
    fprintf(stderr,
            "READY port=%lu ciphersuites=%s groups=%s alpn=%s middlebox=%lu "
            "max_fragment=%lu split_fragment=%lu padding=%zu tcp_nodelay=%d\n",
            port_value, argv[4], argv[5], argv[6], middlebox, max_fragment,
            split_fragment, padding, tcp_nodelay);

    int connection = accept(listener, NULL, NULL);
    if (connection < 0) {
        perror("accept");
        return 1;
    }
    if (setsockopt(connection, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay,
                   sizeof(tcp_nodelay)) != 0) {
        perror("setsockopt(TCP_NODELAY)");
        return 1;
    }
    SSL *ssl = SSL_new(context);
    if (ssl == NULL || SSL_set_fd(ssl, connection) != 1) {
        fail_openssl("SSL setup");
    }
    const int accepted = SSL_accept(ssl);
    if (accepted == 1) {
        fprintf(stderr, "ACCEPTED version=%s cipher=%s group=%s reused=%d\n",
                SSL_get_version(ssl), SSL_get_cipher_name(ssl),
                SSL_get0_group_name(ssl), SSL_session_reused(ssl));
        unsigned char request[4096];
        const int read_count = SSL_read(ssl, request, sizeof(request));
        if (read_count > 0) {
            static const char response[] =
                "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK";
            if (SSL_write(ssl, response, sizeof(response) - 1) <= 0) {
                ERR_print_errors_fp(stderr);
            }
        }
        SSL_shutdown(ssl);
    } else {
        const int error = SSL_get_error(ssl, accepted);
        fprintf(stderr, "SSL_accept ended: ssl_error=%d\n", error);
        ERR_print_errors_fp(stderr);
    }

    SSL_free(ssl);
    close(connection);
    close(listener);
    SSL_CTX_free(context);
    OSSL_PROVIDER_unload(provider);
    return 0;
}
