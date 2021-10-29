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
#include "inttypes.h"

#include "fe-secure-common.h"
#include "libpq-fe.h"
#include "libpq-int.h"

/* A callback that reads bytes from the network. */
int
read_cb(void *userdata, uint8_t *buf, uintptr_t len, uintptr_t *out_n);

/* A callback that writes bytes from the network. */
int
write_cb(void *userdata, const uint8_t *buf, uintptr_t len, uintptr_t *out_n);

uint16_t*
get_tls_versions(uint16_t min, uint16_t max, uint16_t* len);

uint16_t
pg_version_to_rustls_version(char * pg_version);

#ifdef ENABLE_THREAD_SAFETY
#ifndef WIN32
static pthread_mutex_t ssl_config_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
static pthread_mutex_t ssl_config_mutex = NULL;
static long win32_ssl_create_mutex = 0;
#endif
#endif							/* ENABLE_THREAD_SAFETY */

const uint16_t all_tls_versions[6] = {
	RUSTLS_TLS_VERSION_SSLV2,
	RUSTLS_TLS_VERSION_SSLV3,
	RUSTLS_TLS_VERSION_TLSV1_0,
	RUSTLS_TLS_VERSION_TLSV1_1,
	RUSTLS_TLS_VERSION_TLSV1_2,
	RUSTLS_TLS_VERSION_TLSV1_3,
};
const int all_tls_versions_length = 6;

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
}

int
pgtls_init(PGconn *conn, bool do_ssl, bool do_crypto)
{
	if (do_ssl) {
		conn->ssl_in_use = false;
	}
	return 0;
}

void
pgtls_close(PGconn *conn)
{
	ssize_t n;
	if (conn->rustls_conn) {
		rustls_connection_send_close_notify(conn->rustls_conn);
		n = pgtls_write(conn, NULL, 0);
		if(n < 0) {
			// TODO log or return error
		}
		rustls_connection_free(conn->rustls_conn);
		conn->rustls_conn = NULL;
	}
}

uint16_t*
get_tls_versions(uint16_t min, uint16_t max, uint16_t *tls_versions_length)
{
	uint16_t *res;
	int iter = 0;
	uint16_t length = 0;
	for (int i = 0; i < all_tls_versions_length; i++)
	{
		if (min <= all_tls_versions[i] && all_tls_versions[i] <= max)
		{
			length++;
		}
	}
	res = pg_malloc(sizeof(uint16_t)*length);
	for (int i = 0; i < all_tls_versions_length; i++)
	{
		if (min <= all_tls_versions[i] && all_tls_versions[i] <= max)
		{
			res[iter] = all_tls_versions[i];
			iter++;
		}
	}
	*tls_versions_length = length;
	return res;
}

uint16_t
pg_version_to_rustls_version(char * pg_version)
{
	if(strcmp(pg_version, "TLSv1") == 0)
	{
			return RUSTLS_TLS_VERSION_TLSV1_0;
	}
	else if (strcmp(pg_version, "TLSv1.1") == 0)
	{
		return RUSTLS_TLS_VERSION_TLSV1_1;
	}
	else if (strcmp(pg_version, "TLSv1.2") == 0)
	{
		return RUSTLS_TLS_VERSION_TLSV1_2;
	}
	else if (strcmp(pg_version, "TLSv1.3") == 0)
	{
		return RUSTLS_TLS_VERSION_TLSV1_3;
	}
	return 0;
}

PostgresPollingStatusType
pgtls_open_client(PGconn *conn)
{
	size_t tlswritten = 0;
	size_t tls_bytes_read = 0;
	size_t n = 0;
	char errorbuf[255];
	struct rustls_connection *rconn = NULL;
	enum rustls_result result;
	bool wants_read;
	bool wants_write;
	rustls_result rresult = 0;
	rustls_io_result io_error;
	struct rustls_client_config_builder_wants_verifier *config_builder = NULL;
	struct rustls_client_config_builder *config_builder2 = NULL;
	const struct rustls_client_config *client_config = NULL;
	rustls_tls_version min_ssl_version = RUSTLS_TLS_VERSION_TLSV1_2;
	// see https://github.com/rustls/rustls-ffi/issues/146
	rustls_tls_version max_ssl_version = RUSTLS_TLS_VERSION_TLSV1_3;
	bool user_specified_tls_versions = false;
	const uint16_t *tls_versions;
	uint16_t tls_versions_length;

#ifdef ENABLE_THREAD_SAFETY
	if (pthread_mutex_lock(&ssl_config_mutex))
	{
		fprintf(stderr, "unable to lock thread\n");
		printfPQExpBuffer(&conn->errorMessage,
						  libpq_gettext("unable to lock thread"));
		return PGRES_POLLING_FAILED;
	}
#endif

	config_builder = rustls_client_config_builder_new_with_safe_defaults();

	if (conn->ssl_min_protocol_version && strlen(conn->ssl_min_protocol_version) > 0)
	{
		min_ssl_version = pg_version_to_rustls_version(conn->ssl_min_protocol_version);
		if (min_ssl_version == 0)
		{
			appendPQExpBuffer(&conn->errorMessage,
					libpq_gettext("unsupported or unknown minimum TLS version %s\n"),
					conn->ssl_min_protocol_version);
			return PGRES_POLLING_FAILED;
		}
		user_specified_tls_versions = true;
	}

	if (conn->ssl_max_protocol_version && strlen(conn->ssl_max_protocol_version) > 0)
	{
		max_ssl_version = pg_version_to_rustls_version(conn->ssl_max_protocol_version);
		if (max_ssl_version == 0)
		{
			appendPQExpBuffer(&conn->errorMessage,
					libpq_gettext("unsupported or unknown maximum TLS version %s\n"),
					conn->ssl_max_protocol_version);
			return PGRES_POLLING_FAILED;
		}
		user_specified_tls_versions = true;
	}
	if (user_specified_tls_versions)
	{
		tls_versions = get_tls_versions(min_ssl_version, max_ssl_version, &tls_versions_length);
	}
	else
	{
		tls_versions = all_tls_versions;
	}

	result = rustls_client_config_builder_new(
		NULL,
		0,
		tls_versions,
		tls_versions_length,
		&config_builder
	);
	if (result != RUSTLS_RESULT_OK)
	{
		rustls_error(result, errorbuf, sizeof(errorbuf), &n);
		errorbuf[n+1] = '\0';
		appendPQExpBuffer(&conn->errorMessage,
				libpq_gettext("could not build conifguration object: %s\n"),
				errorbuf);

		rustls_client_config_free(
				rustls_client_config_builder_build(config_builder2));
		return PGRES_POLLING_FAILED;
	}

	if (conn->sslrootcert && strlen(conn->sslrootcert) > 0)
	{
		result = rustls_client_config_builder_load_roots_from_file(
				config_builder, conn->sslrootcert, &config_builder2);
		if (result != RUSTLS_RESULT_OK)
		{
			rustls_error(result, errorbuf, sizeof(errorbuf), &n);
			errorbuf[n+1] = '\0';
			appendPQExpBuffer(&conn->errorMessage,
					libpq_gettext("could not load certificates from file %s: %s\n"),
					conn->sslrootcert, errorbuf);

			rustls_client_config_free(
					rustls_client_config_builder_build(config_builder2));
			return PGRES_POLLING_FAILED;
		}
	}
	else
	{
		// TODO load system certs here, or other certs per the initialization
		// settings.
	}

	// rust sets ALPN here, but I don't think that's a thing that Postgres does.
	client_config = rustls_client_config_builder_build(config_builder2);

	result = rustls_client_connection_new(client_config, conn->connhost[conn->whichhost].host, &rconn);
	rustls_client_config_free(client_config);
	if (result != RUSTLS_RESULT_OK)
	{
		// TODO log error here.
		char buf[256];
		size_t n;
		rustls_error(result, buf, sizeof(buf), &n);
		return PGRES_POLLING_FAILED;
	}

	rustls_connection_set_userdata(rconn, conn);
#ifdef ENABLE_THREAD_SAFETY
	pthread_mutex_unlock(&ssl_config_mutex);
#endif

	/* Read/write data until the handshake is done or the socket would block. */
	for (;;)
	{
		/*
		 * Connection has been established according to rustls. Set send/recv
		 * handlers, and update the state machine.
		 * This check has to come last because is_handshaking starts out false,
		 * then becomes true when we first write data, then becomes false again
		 * once the handshake is done.
		 */
		if (!rustls_connection_is_handshaking(rconn))
		{
			conn->rustls_conn = rconn;
			conn->ssl_in_use = true;

			return PGRES_POLLING_OK;
		}

		wants_read = rustls_connection_wants_read(rconn);
		wants_write = rustls_connection_wants_write(rconn);

		/* socket is readable or writable */
		if (wants_write)
		{
			fprintf(stderr, "rustls_connection wants us to write_tls.\n");
			while (rustls_connection_wants_write(rconn))
			{
				io_error = rustls_connection_write_tls(rconn, write_cb,
						conn, &tlswritten);
				if (io_error == EAGAIN || io_error == EWOULDBLOCK)
				{
					continue;
				}
				else if (io_error)
				{
					fprintf(stderr, "got io_error %d\n", io_error);
					rustls_connection_free(rconn);
					return PGRES_POLLING_FAILED;
				}
				if (tlswritten == 0)
				{
					fprintf(stderr, "EOF in swrite\n");
					rustls_connection_free(rconn);
					return PGRES_POLLING_FAILED;
				}
				fprintf(stderr, "rustls_write_tls wrote %ld bytes to network\n", tlswritten);
			}
		}

		if(wants_read) {
			fprintf(stderr, "rustls_connection wants us to read_tls.\n");

			io_error = rustls_connection_read_tls(rconn, read_cb, conn, &tls_bytes_read);
			if(io_error == EAGAIN)
			{
				fprintf(stderr, "sread: EAGAIN or EWOULDBLOCK\n");
			}
			else if(io_error)
			{
				fprintf(stderr, "got io_error %d\n", io_error);
				rustls_connection_free(rconn);
				return PGRES_POLLING_FAILED;
			}
			rresult = rustls_connection_process_new_packets(rconn);
			if(rresult != RUSTLS_RESULT_OK)
			{
				fprintf(stderr, "error processing new packets: %d\n", rresult);
				rustls_connection_free(rconn);
				return PGRES_POLLING_FAILED;
			}

			fprintf(stderr, "rustls_read_tls read %ld bytes from the network\n", tls_bytes_read);
		}
	}


	// returns PGRES_POLLING_FAILED, READING, WRITING, OK, or
	// PGRES_POLLING_ACTIVE
	return PGRES_POLLING_OK;
}

ssize_t
pgtls_read(PGconn *conn, void *ptr, size_t len)
{
	int err = 1;
	int result = 1;
	int n = 0;
	size_t nbytes = 0;
	int read_errno = 0;
	int result_errno = 0;
	size_t plain_bytes_copied = 0;
	char errorbuf[255];
	size_t errorsize = 0;

	fprintf(stderr, "call pgtls_read\n");
	err = rustls_connection_read_tls(conn->rustls_conn, read_cb, conn, &nbytes);
	result_errno = SOCK_ERRNO;
	SOCK_ERRNO_SET(result_errno);
	if (nbytes < 0)
	{
		if (err == EAGAIN || err == EWOULDBLOCK)
		{
			/* no error message, caller is expected to retry */
			fprintf(stderr, "got EAGAIN or EWOULDBLOCK (%d), returning 0 bytes read\n", err);
			n = 0;
			return n;
		}
		else if(err != 0)
		{
			fprintf(stderr, "pgtls_read reading from socket: errno %d\n", err);
			return (ssize_t) n;
		}
	}
	result = rustls_connection_process_new_packets(conn->rustls_conn);
	if(result != RUSTLS_RESULT_OK)
	{
		rustls_error(result, errorbuf, sizeof(errorbuf), &errorsize);
		errorbuf[errorsize+1] = '\0';
		appendPQExpBuffer(&conn->errorMessage,
				libpq_gettext("could not process packets: %s\n"),
				errorbuf);
		return (ssize_t) n;
	}

	while (plain_bytes_copied < len)
	{
		result = rustls_connection_read(conn->rustls_conn, (uint8_t *)ptr + n,
				len - n, &nbytes);
		fprintf(stderr, "rustls_connection_read: read %ld bytes, result %d\n", nbytes, result);
		if(result == RUSTLS_RESULT_ALERT_CLOSE_NOTIFY) {
			fprintf(stderr, "Received close_notify, cleanly ending connection\n");
			return 0;
		} else if (result != RUSTLS_RESULT_OK) {
			rustls_error(result, errorbuf, sizeof(errorbuf), &errorsize);

			errorbuf[errorsize+1] = '\0';
			fprintf(stderr, "could not read tls err: %s\n", errorbuf);
			appendPQExpBuffer(&conn->errorMessage,
					libpq_gettext("could not read TLS: %s\n"),
					errorbuf);
			return plain_bytes_copied;
		} else if (nbytes == 0) {
			// This is expected. It just means "no more bytes for now."
			break;
		} else {
			plain_bytes_copied += nbytes;
			nbytes = 0;
		}
	}

	SOCK_ERRNO_SET(read_errno);
	return plain_bytes_copied;
}

int
read_cb(void *userdata, unsigned char *buf, size_t len, size_t *out_n)
{
	int n = 0;
	PGconn *conn = (PGconn *)userdata;
	n = recv(conn->sock, buf, len, 0);
	if(n < 0) {
		return errno;
	}
	if(out_n != NULL) {
		*out_n = n;
	}
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
	bool out = !rustls_connection_wants_read(conn->rustls_conn);
	return out;
}

/*
 * pgtls_write
 *		Write data on the secure socket
 *
 */
ssize_t
pgtls_write(PGconn *conn, const void *ptr, size_t len)
{
	size_t		plainwritten = 0;
	size_t		nbytes;
	int result = 1;
	int err = 1;
	/// Write up to `count` plaintext bytes from `buf` into the `rustls_connection`.
	/// This will increase the number of output bytes available to
	/// `rustls_connection_write_tls`.
	/// On success, store the number of bytes actually written in *out_n
	/// (this may be less than `count`).
    fprintf(stderr, "call pgtls_write with len %ld\n", len);
	if (len > 0) {
		result = rustls_connection_write(conn->rustls_conn, (uint8_t *)ptr, len, &plainwritten);
		if(result != RUSTLS_RESULT_OK) {
			fprintf(stderr, "error writing plaintext bytes to rustls_connection\n");
			fprintf(stderr, "result: %d\n", result);
			return -1;
		}
		if(plainwritten != len) {
			fprintf(stderr,
					"short write writing plaintext bytes to rustls_connection\n");
			return -1;
		}
	}

	while (rustls_connection_wants_write(conn->rustls_conn)) {
		nbytes = 0;
		err = rustls_connection_write_tls(conn->rustls_conn, write_cb, conn, &nbytes);
		if(err != 0) {
			fprintf(stderr, "Error in rustls_connection_write_tls: errno %d\n", err);
			return -1;
		}
		if (nbytes == 0) {
			// curl handles this as EOF
			fprintf(stderr, "write 0 from rustls_connection_write_tls\n");
			return -1;
		}
		fprintf(stderr, "pg_tls wrote %ld encrypted bytes to the network\n", nbytes);
	}

	fprintf(stderr, "pgtls_write wrote %ld plaintext bytes\n", plainwritten);
	return plainwritten;
}

int
write_cb(void *userdata, const unsigned char *buf, size_t len, size_t *out_n)
{
	ssize_t n = 0;
	int err;
	PGconn *conn = (PGconn *)userdata;

	n = send(conn->sock, buf, len, 0);
	err = SOCK_ERRNO;
	if(n < 0) {
		return err;
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
	fprintf(stderr, "call get peer certificate hash\n");
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
	fprintf(stderr, "verify peer name\n");
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

	if (strcmp(struct_name, "rustls") == 0) {
		return conn->rustls_conn;
	}
	return NULL;
}

/*
 * Return the list of attributes that are supportedby PQsslAttribute below.
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
	uint16_t protocol_version;

	if (!conn || !conn->rustls_conn)
		return NULL;

	if (strcmp(attribute_name, "library") == 0) {
		return "rustls";
    }

	if (strcmp(attribute_name, "protocol") == 0) {
		if (conn->rustls_conn) {
			protocol_version = rustls_connection_protocol_version(conn->rustls_conn);
			switch (protocol_version) {
				case RUSTLS_TLS_VERSION_SSLV2:
					return pstrdup("SSLv2");
				case RUSTLS_TLS_VERSION_SSLV3:
					return pstrdup("SSLv3");
				case RUSTLS_TLS_VERSION_TLSV1_0:
					return "TLSv1.0";
				case RUSTLS_TLS_VERSION_TLSV1_1:
					return "TLSv1.1";
				case RUSTLS_TLS_VERSION_TLSV1_2:
					return "TLSv1.2";
				case RUSTLS_TLS_VERSION_TLSV1_3:
					return "TLSv1.3";
			}
		}
		return pstrdup("unknown");
	}

	if (strcmp(attribute_name, "cipher") == 0) {
		// https://github.com/rustls/rustls/issues/822
		// https://github.com/rustls/rustls-ffi/issues/143
		return pstrdup("unknown");
	}

	// rustls does not support compression
	if (strcmp(attribute_name, "compression") == 0) {
		return "off";
	}

	return NULL;
}
