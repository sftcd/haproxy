/*
 * include/haproxy/ech.h
 * This file provides structures and types for pattern matching.
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

#ifndef _HAPROXY_ECH_H
# define _HAPROXY_ECH_H
# ifdef USE_ECH

/* define this for additional logging of split-mode ECH */
#define ECHDOLOG

#  include <haproxy/ech-t.h>
#  include <openssl/ech.h>
 
int attempt_split_ech(ech_state_t *ech_state,
                      unsigned char *data, size_t bleft,
                      int *dec_ok,
                      unsigned char **newdata, size_t *newlen);

void ech_state_free(ech_state_t *st);

# endif /* USE_ECH */
#endif /* _HAPROXY_ECH_H */
