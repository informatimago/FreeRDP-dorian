/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP X509
 *
 * Copyright 2017 Dorian Ducournau <dorian.ducournau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef X509_H
#define X509_H

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#include <freerdp/log.h>
#include <freerdp/crypto/crypto.h>


#ifndef CERT_INFO_C
#define CERTINFO_EXTERN extern
#else
#define CERTINFO_EXTERN
#endif


typedef const char* ALGORITHM_TYPE;

enum
{
    CERT_CN          =  1, /** Certificate Common Name */
    CERT_SUBJECT     =  2, /** Certificate subject */
    CERT_KPN         =  3, /** Kerberos principal name */
    CERT_EMAIL       =  4, /** Certificate e-mail */
    CERT_UPN         =  5, /** Microsoft's Universal Principal Name */
    CERT_ISSUER      =  6, /** Certificate issuer */
    CERT_KEY_ALG     =  7, /** Certificate key algorithm */
    CERT_INFO_SIZE   = 16, /** Max size of returned certificate content array */
    CERT_INFO_MAX_ENTRIES = (CERT_INFO_SIZE - 1),    /** Max number of entries to find from certificate */
} cert_info_type_enum;
typedef int CERT_INFO_TYPE;


typedef struct
{
	char**   entries;
	unsigned long count;
} x509_cert_info_t;

CERTINFO_EXTERN x509_cert_info_t* x509_cert_info(X509* x509, CERT_INFO_TYPE type);
CERTINFO_EXTERN void x509_cert_info_free(x509_cert_info_t* entries);
CERTINFO_EXTERN char* x509_cert_info_string(X509* x509, CERT_INFO_TYPE type);

#endif
