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

PostgresPollingStatusType
pgtls_open_client(PGconn *conn)
{
	struct rustls_connection *rconn = NULL;
	enum rustls_result result;
	bool wants_read;
	bool wants_write;
	rustls_result rresult = 0;
	rustls_io_result io_error;
	size_t tlswritten = 0;
	size_t tls_bytes_read = 0;
	size_t n = 0;
	char errorbuf[255];
	struct rustls_client_config_builder *config_builder;
	const struct rustls_client_config *client_config = NULL;

	config_builder = rustls_client_config_builder_new();
	if (conn->sslrootcert && strlen(conn->sslrootcert) > 0) {
		result = rustls_client_config_builder_load_roots_from_file(
				config_builder, conn->sslrootcert);
		if(result != RUSTLS_RESULT_OK) {
			/*
			rustls_error(result, errorbuf, sizeof(errorbuf), &n);
			fprintf(stderr, "errorbuf contents: %.*s\n", (int)n, errorbuf);
			fprintf(stderr, "errorbuf contents: %s\n", errorbuf);
			errorbuf[n+1] = '\0';
			printfPQExpBuffer(&conn->errorMessage,
							  "blah blah");
							  */
			rustls_client_config_free(
					rustls_client_config_builder_build(config_builder));
			return PGRES_POLLING_FAILED;
		}
	}
	// TODO load system certs here, or other certs per the initialization
	// settings.
	// rust sets ALPN here but I don't think that's a thing that Postgres does.
	client_config = rustls_client_config_builder_build(config_builder);

	result = rustls_client_connection_new(client_config, conn->connhost[conn->whichhost].host, &rconn);
	rustls_client_config_free(client_config);
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

	/* Read/write data until the handshake is done or the socket would block. */
	for(;;) {
		/*
		 * Connection has been established according to rustls. Set send/recv
		 * handlers, and update the state machine.
		 * This check has to come last because is_handshaking starts out false,
		 * then becomes true when we first write data, then becomes false again
		 * once the handshake is done.
		 */
		if(!rustls_connection_is_handshaking(rconn)) {
			fprintf(stderr, "Done handshaking\n");
			conn->rustls_conn = rconn;
			conn->ssl_in_use = true;

			return PGRES_POLLING_OK;
		}

		wants_read = rustls_connection_wants_read(rconn);
		wants_write = rustls_connection_wants_write(rconn);

		/* socket is readable or writable */
		if(wants_write) {
			fprintf(stderr, "rustls_connection wants us to write_tls.\n");
			while(rustls_connection_wants_write(rconn)) {
				io_error = rustls_connection_write_tls(rconn, write_cb,
						conn, &tlswritten);
				if(io_error == EAGAIN || io_error == EWOULDBLOCK) {
					continue;
				} else if(io_error) {
					fprintf(stderr, "got io_error %d\n", io_error);
					rustls_connection_free(rconn);
					return PGRES_POLLING_FAILED;
				}
				if(tlswritten == 0) {
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
			if(io_error == EAGAIN) {
				fprintf(stderr, "sread: EAGAIN or EWOULDBLOCK\n");
			} else if(io_error) {
				fprintf(stderr, "got io_error %d\n", io_error);
				rustls_connection_free(rconn);
				return PGRES_POLLING_FAILED;
			}
			rresult = rustls_connection_process_new_packets(rconn);
			if(rresult != RUSTLS_RESULT_OK) {
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
	int			read_errno = 0;
	int			result_errno = 0;
	size_t plain_bytes_copied = 0;
	char		sebuf[PG_STRERROR_R_BUFLEN];

	fprintf(stderr, "call pgtls_read\n");

	/*
	   n = recv(conn->sock, ptr, len, 0);
	   fprintf(stderr, "recv %d bytes\n", n);
	   if (n < 0)
	   {
	   result_errno = SOCK_ERRNO;
	   fprintf(stderr, "got errno %d\n", result_errno);
	// *//* Set error message if appropriate *//*
	switch (result_errno)
	{
#ifdef EAGAIN
		case EAGAIN:
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
		case EWOULDBLOCK:
#endif
		case EINTR:
			*//* no error message, caller is expected to retry *//*
																	break;

																	case EPIPE:
																	case ECONNRESET:
																	appendPQExpBufferStr(&conn->errorMessage,
																	libpq_gettext("server closed the connection unexpectedly\n"
																	"\tThis probably means the server terminated abnormally\n"
																	"\tbefore or while processing the request.\n"));
																	break;

																	default:
																	appendPQExpBuffer(&conn->errorMessage,
																	libpq_gettext("could not receive data from server: %s\n"),
																	SOCK_STRERROR(result_errno,
																	sebuf, sizeof(sebuf)));
																	break;
																	}
																	}

*//* ensure we return the intended errno to caller *//*
														SOCK_ERRNO_SET(result_errno);

														return n;

*/
				// this one calls recv - the read() in whe while loop just reads from the
				// internal buffer.
				err = rustls_connection_read_tls(conn->rustls_conn, read_cb, conn, &nbytes);
			result_errno = SOCK_ERRNO;
			SOCK_ERRNO_SET(result_errno);
			if (nbytes < 0) {
				if (err == EAGAIN || err == EWOULDBLOCK) {
					/* no error message, caller is expected to retry */
					fprintf(stderr, "got EAGAIN or EWOULDBLOCK (%d), returning 0 bytes read\n", err);
					n = 0;
					return n;
				} else if(err != 0) {
					fprintf(stderr, "pgtls_read reading from socket: errno %d\n", err);
					return (ssize_t) n;
				}
			}
			result = rustls_connection_process_new_packets(conn->rustls_conn);
			if(result != RUSTLS_RESULT_OK) {
				fprintf(stderr, "processing new packets: result %d\n", result);
				return (ssize_t) n;
			}

			while (plain_bytes_copied < len) {
				result = rustls_connection_read(conn->rustls_conn, (uint8_t *)ptr + n,
						len - n, &nbytes);
				fprintf(stderr, "rustls_connection_read: read %ld bytes, result %d\n", nbytes, result);
				if(result == RUSTLS_RESULT_ALERT_CLOSE_NOTIFY) {
					fprintf(stderr, "Received close_notify, cleanly ending connection\n");
					return 0;
				} else if (result != RUSTLS_RESULT_OK) {
					fprintf(stderr, "Error in rustls_connection_read: %d\n", result);
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
	uint16_t protocol_version;
    rustls_supported_ciphersuite csuite;
	fprintf(stderr, "get attribute name %s\n", attribute_name);

	if (!conn || !conn->rustls_conn)
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

	 */
	if (strcmp(attribute_name, "protocol") == 0) {
		if (conn->rustls_conn) {
			protocol_version = rustls_connection_get_protocol_version(conn->rustls_conn);
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
