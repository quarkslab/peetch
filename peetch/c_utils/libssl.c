// SPDX-License-Identifier: GPL-2.0+
// Guillaume Valadon <gvaladon@quarkslab.com>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/ssl.h>

#define STRUCTURE_SIZE 8192

struct libssl_offsets_t {
  uint64_t ssl_session;
  uint64_t ssl_cipher;
  uint64_t master_secret;
};


struct libssl_offsets_t libssl_offsets(char *ip4_address, uint16_t port) {
  struct libssl_offsets_t offsets = { .ssl_session = 0,
                                      .ssl_cipher = 0, .master_secret = 0};

  // Create the SSL context and set the TLS version
  const SSL_METHOD *method = TLS_client_method();
  SSL_CTX *ctx = SSL_CTX_new(method);

  int ret = SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  if (ret < 0) {
    printf("SSL_CTX_set_max_proto_version() error - %d\n", ret);
    return offsets;
  }

  // Set up a TLS connection to get the SSL session structure
  SSL *ssl = SSL_new(ctx);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    printf("socket() error - %d\n", fd);
    return offsets;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  ret = inet_aton(ip4_address, (struct in_addr*) &addr.sin_addr.s_addr);
  if (ret < 0) {
    printf("inet_aton() error - %d\n", fd);
    return offsets;
  }

  ret = connect(fd, (struct sockaddr*) &addr, sizeof(addr));
  if (ret < 0) {
    printf("connect() error - %d\n", fd);
    return offsets;
  }

  ret = SSL_set_fd(ssl, fd);
  if (ret < 0) {
    printf("SSL_set_fd() error - %d\n", fd);
    return offsets;
  }

  ret = SSL_connect(ssl);
  if (ret < 0) {
    printf("SSL_connect() error - %d\n", fd);
    return offsets;
  }

  // SSL_SESSION* offset
  SSL_SESSION *session = SSL_get_session(ssl);
  for (uint64_t i = 0x000; i < STRUCTURE_SIZE; i++) {
    uint64_t value = (uint64_t) ssl + i;
    uint64_t *ptr = (uint64_t*) value;
    if ((uint64_t) *ptr == (uint64_t) session) {
      offsets.ssl_session = i;
      break;
    }
  }

  // SSL_CIPHER* offset
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  for (uint64_t i = 0x000; i < STRUCTURE_SIZE; i++) {
    uint64_t value = (uint64_t) session + i;
    uint64_t *ptr = (uint64_t*) value;
    if ((uint64_t) *ptr == (uint64_t) cipher) {
      offsets.ssl_cipher = i;
      break;
    }
  }

  // TLS 1.2 MASTER_SECRET offset
  uint8_t master_secret[48];
  ret = SSL_SESSION_get_master_key(session,
                                  (char*)&master_secret, sizeof(master_secret));
  if (ret != 48) {
    printf("SSL_SESSION_get_master_key() error - %d\n", fd);
    return offsets;
  }
  for (uint64_t i=0x000; i < STRUCTURE_SIZE; i++) {
    uint64_t value = (uint64_t) session + i;
    uint64_t *ptr = (uint64_t*) value;
    value = (uint64_t) session + i + 47;
    uint64_t *ptr_end = (uint64_t*) value;
    if ((*ptr & 0xFF) == master_secret[0] && \
        (*ptr_end & 0xFF) == master_secret[47]) {
      offsets.master_secret = i;
      break;
    }
  }
  return offsets;
}


int main() {
 /*
 Compile it with:
 cc -o libssl_offsets libssl.c -lssl
 */
  struct libssl_offsets_t offsets = libssl_offsets("1.1.1.1", 443);
  printf("--ssl_session_offset=0x%lx\n", offsets.ssl_session);
  printf("--ssl_cipher_offset=0x%lx\n", offsets.ssl_cipher);
  printf("--master_secret_offset=0x%lx\n", offsets.master_secret);

  return EXIT_SUCCESS;
}
