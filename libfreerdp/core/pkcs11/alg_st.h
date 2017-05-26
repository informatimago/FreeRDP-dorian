/*
 * PKCS #11 PAM Login Module
 * Copyright (C) 2003-2004 Mario Strasser <mast@gmx.net>
 * Copyright (C) 2005 Juan Antonio Martinez <jonsito@teleline.es>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * $Id$
 */

#ifndef ALG_ST_H
#define ALG_ST_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/evp.h>
typedef EVP_MD ALGDIGEST;
#define ALGORITHM_SHA512 "sha512"
#define ALGORITHM_SHA384 "sha384"
#define ALGORITHM_SHA256 "sha256"
#define ALGORITHM_SHA1  "sha1"
#define ALGORITHM_MD5  "md5"
#define ALGORITHM_MD2  "md2"

ALGORITHM_TYPE Alg_get_alg_from_string(const char *);
/* EVP_get_digestbyname */
const ALGDIGEST *Alg_get_digest_by_name(ALGORITHM_TYPE hash);

#endif /* ALG_ST_H */
