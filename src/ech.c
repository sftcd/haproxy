/*
 * ECH utility functions
 *
 * Copyright 2023 Stephen Farrell <stephen.farrell@cs.tcd.ie>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <haproxy/buf-t.h>
#include <haproxy/ech.h>

int attempt_split_ech(ech_state_t *ech_state,
                      unsigned char *data, size_t bleft,
                      int *dec_ok,
                      unsigned char **newdata, size_t *newlen)
{
    size_t chlen = 0, hs_len = 0;
    unsigned char *ch = data, *orig = data;
    int srv = 0, isccs = 0;
    char *newinner = NULL, *newouter = NULL;

	/* Check for SSL/TLS Handshake */
	if (!bleft)
		goto err;

	if (*data != 0x16 && *data != 0x14)
		goto err;
    if (*data == 0x14) {
        isccs = 1; /* we have a fakey change cipher suite */
        data += 6;
        ch = data;
        bleft -= 6;
    }
	/* Check for SSLv3 or later (SSL version >= 3.0) in the record layer*/
	if (bleft < 3)
		goto err;
	if (data[1] < 0x03)
		goto err;
	if (bleft < 5)
		goto err;
	hs_len = (data[3] << 8) + data[4];
    chlen=hs_len+5;
	if (hs_len < 1 + 3 + 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2)
		goto err;
	data += 5; /* enter TLS handshake */
	bleft -= 5;
	/* Check for a complete client hello starting at <data> */
	if (bleft < 1)
		goto err;
	if (data[0] != 0x01) /* msg_type = Client Hello */
		goto err;
	/* Check the Hello's length */
	if (bleft < 4)
		goto err;
	hs_len = (data[1] << 16) + (data[2] << 8) + data[3];
	if (hs_len < 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + 2)
		goto err;
	/* We want the full handshake here */
    /* TODO: maybe handle early data here? */
	if (bleft < hs_len)
		goto err;
    *newlen = chlen + (isccs ? 6 : 0);
    *newdata = OPENSSL_malloc(*newlen);
    if (*newdata == NULL)
		goto err;
    if (isccs) {
        memcpy(*newdata, orig, 6);
    }
    /* Attempt to decrypt and retrieve inner/outer SNI values */
    srv = SSL_CTX_ech_raw_decrypt(ech_state->ctx, dec_ok,
                                  &newinner, &newouter,
                                  ch, chlen,
                                  (*newdata + (isccs ? 6 : 0)), newlen,
                                  &ech_state->hrrtok, &ech_state->toklen);
    if (srv != 1)
        OPENSSL_free(*newdata);
    if (srv == 1 && isccs)
        *newlen += 6;

    /* check/copy new inner */
    if (srv == 1 && ech_state->inner_sni != NULL) {
        if (newinner == NULL) {
            /* error - TOD: log & clean up */
            return 0;
        } else {
            size_t nilen = strlen(newinner);
            size_t oilen = strlen(ech_state->inner_sni);
            if (nilen != oilen) {
                /* error - TOD: log & clean up */
                return 0;
            } 
            if (strncmp(newinner, ech_state->inner_sni, nilen)) {
                /* error - TOD: log & clean up */
                return 0;
            }
            OPENSSL_free(newinner);
        }
    } else {
        if (newinner != NULL) {
            /* error - TOD: log & clean up */
            return 0;
        }
    }

    /* check/copy new outer */
    if (srv == 1 && ech_state->outer_sni != NULL) {
        if (newouter == NULL) {
            /* error - TOD: log & clean up */
            return 0;
        } else {
            size_t nilen = strlen(newouter);
            size_t oilen = strlen(ech_state->outer_sni);
            if (nilen != oilen) {
                /* error - TOD: log & clean up */
                return 0;
            } 
            if (strncmp(newouter, ech_state->outer_sni, nilen)) {
                /* error - TOD: log & clean up */
                return 0;
            }
            OPENSSL_free(newouter);
        }
    } else {
        if (newouter != NULL) {
            /* error - TOD: log & clean up */
            return 0;
        }
    }

    return srv;
err:
    return 0;
}

void ech_state_free(ech_state_t *st)
{
    if (st == NULL)
        return;
    /* st->ctx is a shallow copy, so doesn't need freeing */
    OPENSSL_free(st->hrrtok);
    OPENSSL_free(st->inner_sni);
    OPENSSL_free(st->outer_sni);
    return;
}
