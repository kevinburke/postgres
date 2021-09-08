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

#include "fe-secure-common.h"
#include "libpq-fe.h"
#include "libpq-int.h"

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
	return 0;
}

void
pgtls_close(PGconn *conn)
{
}

PostgresPollingStatusType
pgtls_open_client(PGconn *conn)
{
    // returns PGRES_POLLING_FAILED, READING, WRITING, OK, or
    // PGRES_POLLING_ACTIVE
	return PGRES_POLLING_OK;
}

ssize_t
pgtls_read(PGconn *conn, void *ptr, size_t len)
{
	PRInt32		nread;
	return (ssize_t) nread;
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
    return false;
}

/*
 * pgtls_write
 *		Write data on the secure socket
 *
 */
ssize_t
pgtls_write(PGconn *conn, const void *ptr, size_t len)
{
	PRInt32		n;
	return (ssize_t) n;
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
