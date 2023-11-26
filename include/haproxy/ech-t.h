/*
 * include/haproxy/ech-t.h
 * This file provides structures and types for MAPs.
 *
 * Copyright (C) 2023 Stephen Farrell stephen.farrell@cs.tcd.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_ECH_T_H
#define _HAPROXY_ECH_T_H

#include <openssl/ssl.h>

typedef struct ech_state_ts {
    SSL_CTX *ctx;
    int calls;
    unsigned char *hrrtok;
    size_t toklen;
    char *inner_sni;
    char *outer_sni;
} ech_state_t;

#endif /* _HAPROXY_ECH_T_H */
