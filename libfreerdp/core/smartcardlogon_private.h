/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Smartcard logon  private header.
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

#ifndef LIBFREERDP_CORE_SMARTCARDLOGON_PRIVATE_H
#define LIBFREERDP_CORE_SMARTCARDLOGON_PRIVATE_H


#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#include <gssapi/gssapi.h>

#include "freerdp/freerdp.h"
#include "freerdp/crypto/crypto.h"

#define MAX_KEYS_PER_SLOT 15
#define NB_ENTRIES_MAX 20
#define SIZE_SPN_MAX 200
#define PIN_LENGTH 4
#define SIZE_TOKEN_LABEL_MAX 30
#define SIZE_NB_SLOT_ID_MAX 2 /* "99" slots max */
#define NB_TRY_MAX_LOGIN_TOKEN 3

#define FLAGS_TOKEN_USER_PIN_NOT_IMPLEMENTED    (0)
#define FLAGS_TOKEN_USER_PIN_OK        		(0)

/*
 * token flag values meet kerberos responder pkinit flags defined in krb5.h
 * KRB5_RESPONDER_PKINIT_FLAGS_TOKEN_USER_PIN_COUNT_LOW (1 << 0)
 * KRB5_RESPONDER_PKINIT_FLAGS_TOKEN_USER_PIN_FINAL_TRY (1 << 1)
 * KRB5_RESPONDER_PKINIT_FLAGS_TOKEN_USER_PIN_LOCKED	(1 << 2)
 */
#define FLAGS_TOKEN_USER_PIN_COUNT_LOW  		(1 << 0)
#define FLAGS_TOKEN_USER_PIN_FINAL_TRY  		(1 << 1)
#define FLAGS_TOKEN_USER_PIN_LOCKED     		(1 << 2)



typedef struct cert_object
{
	CK_KEY_TYPE key_type;
	CK_CERTIFICATE_TYPE type;
	char* id_cert;
	CK_OBJECT_HANDLE private_key;
	X509* x509;
}  cert_object;

typedef struct cert_policy
{
	int ca_policy;
	int crl_policy;
	int signature_policy;
	const char* ca_dir;
	const char* crl_dir;
	int ocsp_policy;
}  cert_policy;


#define PKCS11_MODULE_MAGIC			0xd00bed00

typedef struct pkcs11_module
{
	unsigned int magic;
	void* library;
	CK_FUNCTION_LIST_PTR p11;
}  pkcs11_module;

typedef struct pkcs11_context
{
	pkcs11_module* module;
	CK_SLOT_ID slot_id;
	CK_ULONG slot_count;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE private_key;
	cert_policy policy;
	int certificates_count;
	cert_object** certificates;
	cert_object* valid_cert;
} pkcs11_context;

#endif
