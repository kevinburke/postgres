/*-------------------------------------------------------------------------
 *
 * fe-secure-rustls.c
 *	  functions for supporting NSS as a TLS backend for frontend libpq
 *
 * Portions Copyright (c) 1996-2021, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/interfaces/libpq/fe-secure-rustls.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"
#include "crustls.h"

#include "fe-secure-common.h"
#include "libpq-fe.h"
#include "libpq-int.h"

/* A callback that reads bytes from the network. */
int
read_cb(void *userdata, uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* A callback that writes bytes from the network. */
int
write_cb(void *userdata, const uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* ------------------------------------------------------------ */
/*			 Procedures common to all secure sessions			*/
/* ------------------------------------------------------------ */

/*
 * pgtls_init_library
 */
void
pgtls_init_library(bool do_ssl, int do_crypto)
{
	/* noop */
	fprintf(stderr, "call pgtls_init_library\n");
}

int
pgtls_init(PGconn *conn, bool do_ssl, bool do_crypto)
{
	fprintf(stderr, "call pgtls_init\n");
	if (do_ssl) {
		conn->rustls_config = NULL;
		conn->ssl_in_use = false;
	}
	return 0;
}

void
pgtls_close(PGconn *conn)
{
}

PostgresPollingStatusType
pgtls_open_client(PGconn *conn)
{
	fprintf(stderr, "call pgtls_open_client\n");
	struct rustls_connection *rconn = NULL;
	enum rustls_result result;

	struct rustls_client_config_builder *config_builder =
		rustls_client_config_builder_new();
	// TODO load certs here.
	const struct rustls_client_config *client_config = NULL;
	// rust sets ALPN here but I don't think that's a thing that Postgres does.
	client_config = rustls_client_config_builder_build(config_builder);

	result = rustls_client_connection_new(client_config, conn->connhost[conn->whichhost].host, &rconn);
	if(result != RUSTLS_RESULT_OK) {
		// TODO log error here.
		char buf[256];
		size_t n;
		rustls_error(result, buf, sizeof(buf), &n);
		fprintf(stderr, "could not create connection/handshake: %.*s\n", (int)n, buf);
		return PGRES_POLLING_FAILED;
	}
	fprintf(stderr, "created rustls connection\n");

	rustls_connection_set_userdata(rconn, conn);
	conn->rustls_conn = rconn;

	conn->ssl_in_use = true;
    // returns PGRES_POLLING_FAILED, READING, WRITING, OK, or
    // PGRES_POLLING_ACTIVE
	return PGRES_POLLING_OK;
}

ssize_t
pgtls_read(PGconn *conn, void *ptr, size_t len)
{
	printf("call pgtls_read\n");
	int err = 1;
	int result = 1;
	size_t n = 0;
	size_t nbytes = 0;
	int			read_errno = 0;
	// inside of do_read
	err = rustls_connection_read_tls(conn->rustls_conn, read_cb, conn, &nbytes);
	if (err == EAGAIN || err == EWOULDBLOCK) {
		/* no error message, caller is expected to retry */
		SOCK_ERRNO_SET(err);
		return (ssize_t) n;
	}
	else if(err != 0) {
		fprintf(stderr, "reading from socket: errno %d\n", err);
		SOCK_ERRNO_SET(err);
		return (ssize_t) n;
	}
	result = rustls_connection_process_new_packets(conn->rustls_conn);
	if(result != RUSTLS_RESULT_OK) {
		fprintf(stderr, "processing new packets: result %d\n", result);
		return (ssize_t) n;
	}

	// copy data to ptr
	fprintf(stderr, "read data into ptr with len %d\n", len);
	result = rustls_connection_read(conn->rustls_conn, ptr, len, &nbytes);
	n += nbytes;
	if(result == RUSTLS_RESULT_ALERT_CLOSE_NOTIFY) {
		fprintf(stderr, "Received close_notify, cleanly ending connection\n");
		return n;
	}
	if(result != RUSTLS_RESULT_OK) {
		fprintf(stderr, "Error in rustls_connection_read: %d\n", result);
		return n;
	}
	if(n == 0) {
		/* This is expected. It just means "no more bytes for now." */
		return n;
	}
	ptr += nbytes;
	len -= nbytes;

	SOCK_ERRNO_SET(read_errno);
	return (ssize_t) n;
}

int
read_cb(void *userdata, unsigned char *buf, size_t len, size_t *out_n)
{
  ssize_t n = 0;
  PGconn *conn = (PGconn *)userdata;
  n = recv(conn->sock, buf, len, 0);
  if(n < 0) {
	fprintf(stderr, "got errno: %d\n", errno);
    return errno;
  }
  if(out_n != NULL) {
    *out_n = n;
  }
  printf("read data %s\n", buf);
  return 0;
}

/*
 * pgtls_read_pending
 *		Check for the existence of data to be read
 *
 * SSL_DataPending will check for decrypted data in the receiving buffer, but
 * does not reveal anything about still encrypted data which will be made
 * available. Thus, if pgtls_read_pending returns zero it does not guarantee
 * that a subsequent call to pgtls_read_read would block. This is modelled
 * around how the OpenSSL implementation treats pending data. The equivalent
 * to the OpenSSL SSL_has_pending function would be to call PR_Recv with no
 * wait and PR_MSG_PEEK like so:
 *
 *     PR_Recv(conn->pr_fd, &c, 1, PR_MSG_PEEK, PR_INTERVAL_NO_WAIT);
 */
bool
pgtls_read_pending(PGconn *conn)
{
	printf("pgtls read pending\n");
	return rustls_connection_wants_read(conn->rustls_conn);
}

/*
 * pgtls_write
 *		Write data on the secure socket
 *
 */
ssize_t
pgtls_write(PGconn *conn, const void *ptr, size_t len)
{
	printf("call rustls write\n");
	int		n;
	int		nbytes;
	int result = 1;
	int err = 1;
	/// Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
	/// This will increase the number of output bytes available to
	/// `rustls_connection_write_tls`.
	/// On success, store the number of bytes actually written in *out_n
	/// (this may be less than `count`).
	result = rustls_connection_write(conn->rustls_conn, ptr, len, &n);
	if(result != RUSTLS_RESULT_OK) {
		fprintf(stderr, "error writing plaintext bytes to rustls_connection\n");
		fprintf(stderr, "result: %d\n");
		return -1;
	}
	if(n != len) {
		fprintf(stderr,
				"short write writing plaintext bytes to rustls_connection\n");
		return -1;
	}

	fprintf(stderr, "wrote %d plaintext bytes\n", n);
	for(;;) {
		if(!rustls_connection_wants_write(conn->rustls_conn)) {
			fprintf(stderr, "rustls connection does not want write anymore\n");
			break;
		}

		nbytes = 0;
		err = rustls_connection_write_tls(conn->rustls_conn, write_cb, conn, &nbytes);
		if(err != 0) {
			fprintf(stderr, "Error in rustls_connection_write_tls: errno %d\n", err);
			return -1;
		}
		if (nbytes == 0) {
			fprintf(stderr, "write 0 from rustls_connection_write_tls\n");
			break;
		}
		fprintf(stderr, "write %d bytes from rustls_connection_write_tls\n", nbytes);
	}

	return (ssize_t) n;
}

int
write_cb(void *userdata, const unsigned char *buf, size_t len, size_t *out_n)
{
  ssize_t n = 0;
  PGconn *conn = (PGconn *)userdata;

  n = send(conn->sock, buf, len, 0);
  if(n < 0) {
    return errno;
  }
  if(out_n != NULL) {
    *out_n = n;
  }
  return 0;
}


char *
pgtls_get_peer_certificate_hash(PGconn *conn, size_t *len)
{
	char	   *ret = NULL;
	ret = pg_malloc(1);
    return ret;
}

/*
 *	Verify that the server certificate matches the hostname we connected to.
 *
 * The certificate's Common Name and Subject Alternative Names are considered.
 */
int
pgtls_verify_peer_name_matches_certificate_guts(PGconn *conn,
												int *names_examined,
												char **first_name)
{
    return 0;
}

/*
 * PQgetssl
 *
 * Return NULL as this is legacy and defined to always be equal to calling
 * PQsslStruct(conn, "OpenSSL"); This should ideally trigger a logged warning
 * somewhere as it's nonsensical to run in a non-OpenSSL build.
 */
void *
PQgetssl(PGconn *conn)
{
	return NULL;
}

void *
PQsslStruct(PGconn *conn, const char *struct_name)
{
	if (!conn)
		return NULL;

	/*
	 * Return the underlying PRFileDesc which can be used to access
	 * information on the connection details. There is no SSL context per se.
	 */

    /*
     * TODO rust specific information
	if (strcmp(struct_name, "NSS") == 0)
		return conn->pr_fd;
     */
	return NULL;
}

/*
 * not sure what this is
 */
const char *const *
PQsslAttributeNames(PGconn *conn)
{
	static const char *const result[] = {
		"library",
		"cipher",
		"protocol",
		"key_bits",
		"compression",
		NULL
	};

	return result;
}

const char *
PQsslAttribute(PGconn *conn, const char *attribute_name)
{
    /*
	SECStatus	status;
	SSLChannelInfo channel;
	SSLCipherSuiteInfo suite;
    */

	if (!conn || !conn->pr_fd)
		return NULL;

	if (strcmp(attribute_name, "library") == 0)
		return "rustls";

    /*
     * TODO
	status = SSL_GetChannelInfo(conn->pr_fd, &channel, sizeof(channel));
	if (status != SECSuccess)
		return NULL;

	status = SSL_GetCipherSuiteInfo(channel.cipherSuite, &suite, sizeof(suite));
	if (status != SECSuccess)
		return NULL;

	if (strcmp(attribute_name, "cipher") == 0)
		return suite.cipherSuiteName;

	if (strcmp(attribute_name, "key_bits") == 0)
	{
		static char key_bits_str[8];

		snprintf(key_bits_str, sizeof(key_bits_str), "%i", suite.effectiveKeyBits);
		return key_bits_str;
	}

	if (strcmp(attribute_name, "protocol") == 0)
		return ssl_protocol_version_to_string(channel.protocolVersion);

	 * NSS disabled support for compression in version 3.33, and it was only
	 * available for SSLv3 at that point anyways, so we can safely return off
	 * here without even checking.
	if (strcmp(attribute_name, "compression") == 0)
		return "off";
    */
	return NULL;
}
