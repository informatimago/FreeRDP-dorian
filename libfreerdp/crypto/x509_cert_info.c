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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/ossl_typ.h>
#include <openssl/x509.h>

#include <winpr/crt.h>
#include <winpr/crypto.h>

#include <freerdp/log.h>
#include <freerdp/crypto/crypto.h>
char* crypto_print_name(X509_NAME* name);


#define TAG FREERDP_TAG("core.x509")


static void*  check_out_of_memory_error(void* pointer)
{
	if (!pointer)
	{
		WLog_ERR(TAG, "Out of memory error (malloc returned NULL)");
	}

	return pointer;
}

static inline void report_x509_error(const char* operation)
{
	WLog_ERR(TAG, "%s() failed: %s", operation, ERR_error_string(ERR_get_error(), NULL));
}

static char* x509_name_entry_to_utf8_string(X509_NAME* name, int loc)
{
	X509_NAME_ENTRY* entry;
	ASN1_STRING* asn1string;
	unsigned char* string;
	char* result;

	if (!(entry = X509_NAME_get_entry(name, loc)))
	{
		report_x509_error("X509_NAME_get_entry");
		return 0;
	}

	if (!(asn1string = X509_NAME_ENTRY_get_data(entry)))
	{
		report_x509_error("X509_NAME_ENTRY_get_data");
		return 0;
	}

	if (ASN1_STRING_to_UTF8(&string, asn1string) < 0)
	{
		report_x509_error("ASN1_STRING_to_UTF8");
		return 0;
	}

	result = strdup((char *)string);
	OPENSSL_free(string);
	return result;
}



static char*  x509_name_to_utf8_string(X509_NAME* name)
{
	return crypto_print_name(name);
}


static x509_cert_info_t* x509_cert_info_alloc(unsigned long count)
{
	x509_cert_info_t* result = check_out_of_memory_error(malloc(sizeof(*result)));

	if (result != 0)
	{
		unsigned long i;
		/* We allocate one more entry, so result->entries[] is null-terminated,
                in addition to the result->count field. */
		result->entries = check_out_of_memory_error(malloc(sizeof(result->entries[0]) * (count + 1)));

		if (!result->entries)
		{
			free(result);
			return 0;
		}

		for (i = 0; i <= count; i ++)
		{
			result->entries[i] = 0;
		}

		result->count = count;
	}

	return result;
}


CERTINFO_EXTERN void x509_cert_info_free(x509_cert_info_t* info)
{
	unsigned long i;

	if (!info)
	{
		return;
	}

	for (i = 0; i < info->count; i ++)
	{
		free(info->entries[i]);
		info->entries[i] = 0;
	}

	free(info);
}


/*
* Extract Certificate's Common Name
*/
static x509_cert_info_t* cert_info_cn(X509* x509)
{
	x509_cert_info_t* result = x509_cert_info_alloc(CERT_INFO_SIZE);
	X509_NAME* name = X509_get_subject_name(x509);
	int lastpos, position;

	if (!name)
	{
		WLog_ERR(TAG, "Certificate has no subject");
		goto fail;
	}

	position = 0;
	lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, -1);

	if (lastpos == -1)
	{
		WLog_ERR(TAG, "Certificate has no UniqueID");
		goto fail;
	}

	while ((lastpos != -1) && (position < CERT_INFO_MAX_ENTRIES))
	{
		char* string = x509_name_entry_to_utf8_string(name, lastpos);

		if (!string)
		{
                        result->count = position;
                        return result;
		}

		WLog_INFO(TAG, "%s = [%s]", OBJ_nid2sn(NID_commonName), string);
		result->entries[position++] = string;
		lastpos = X509_NAME_get_index_by_NID(name, NID_commonName, lastpos);
	}

	/* no more UID's available in certificate */
        result->count = position;
	return result;
fail:
	x509_cert_info_free(result);
	return NULL;
}


typedef X509_NAME* (* get_field_pr)(X509* x509);
static x509_cert_info_t* cert_info_field(X509* x509, get_field_pr get_field, const char* operation)
{
	x509_cert_info_t* result;
	X509_NAME* field;

	if (!(field = get_field(x509)))
	{
		report_x509_error(operation);
		return 0;
	}

	if (!(result = x509_cert_info_alloc(1)))
	{
		return 0;
	}

	char* string = x509_name_to_utf8_string(field);

	if (!string)
	{
                result->count = 0;
		return result;
	}

	result->entries[0] = string;
        result->count = 1;
	return result;
}

static x509_cert_info_t* cert_info_subject(X509* x509)
{
	return cert_info_field(x509, X509_get_subject_name, "X509_get_subject_name");
}

static x509_cert_info_t* cert_info_issuer(X509* x509)
{
	return cert_info_field(x509, X509_get_issuer_name, "X509_get_issuer_name");
}


typedef char *  (* extractor_pr)(ASN1_TYPE * value);

static char * cert_info_get_othername(X509* x509, ASN1_OBJECT * type_id, extractor_pr extract)
{
        char *  result = 0;
        int i;
	STACK_OF(GENERAL_NAME) *gens;
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (!gens)
	{
                return 0;
	}
        WLog_DBG(TAG, "subjectAltName: found %d names", sk_GENERAL_NAME_num(gens));
	for (i = 0; (i < sk_GENERAL_NAME_num(gens)); i++)
	{
                GENERAL_NAME* name = sk_GENERAL_NAME_value(gens, i);

                static const char *  general_name_types[] = { "OTHERNAME",
                                                              "EMAIL    ",
                                                              "DNS      ",
                                                              "X400     ",
                                                              "DIRNAME  ",
                                                              "EDIPARTY ",
                                                              "URI      ",
                                                              "IPADD    ",
                                                              "RID      "};
                if (name)
                {
                        const char *  type = "";
                        if ((0 <= name->type) && (name->type < countof(general_name_types))){
                                type = general_name_types[name->type];
                        }
                        WLog_DBG(TAG, "name[%d] =  %s (%d)",i, type, name->type);
                }else
                {
                        WLog_ERR(TAG, "name[%d] =  (null) !!!",i);
                }


		if (name && name->type == GEN_OTHERNAME)
		{
                        WLog_DBG(TAG, "otherName: found a %s (%d)",
                                OBJ_nid2ln(OBJ_obj2nid(name->d.otherName->type_id)),
                                OBJ_obj2nid(name->d.otherName->type_id));
			if (OBJ_cmp(name->d.otherName->type_id, type_id))
			{
				continue;
			}
                        result = extract(name->d.otherName->value);
                        if (result)
                        {
                                WLog_DBG(TAG, "otherName: extracted %s (%d) value: %s",
                                        OBJ_nid2ln(OBJ_obj2nid(name->d.otherName->type_id)),
                                        OBJ_obj2nid(name->d.otherName->type_id),
                                        result);
                                break;
                        }
		}
	}
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	return result;
}

static char * cert_info_get_email(X509* x509)
{
        char *  result = 0;
        int i;
	STACK_OF(GENERAL_NAME) *gens;
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (!gens)
	{
                return 0;
	}
        WLog_DBG(TAG, "subjectAltName: found %d names", sk_GENERAL_NAME_num(gens));
	for (i = 0; (i < sk_GENERAL_NAME_num(gens)); i++)
	{
                GENERAL_NAME* name = sk_GENERAL_NAME_value(gens, i);

                static const char *  general_name_types[] = { "OTHERNAME",
                                                              "EMAIL    ",
                                                              "DNS      ",
                                                              "X400     ",
                                                              "DIRNAME  ",
                                                              "EDIPARTY ",
                                                              "URI      ",
                                                              "IPADD    ",
                                                              "RID      "};

                if (name)
                {
                        const char *  type = "";
                        if ((0 <= name->type) && (name->type < countof(general_name_types))){
                                type = general_name_types[name->type];
                        }
                        WLog_DBG(TAG, "name[%d] =  %s (%d)",i, type, name->type);
                }else
                {
                        WLog_ERR(TAG, "name[%d] =  (null) !!!",i);
                }


		if (name && name->type == GEN_EMAIL)
		{
                        unsigned char* cstring = 0;
                        ASN1_STRING* str = name->d.rfc822Name;
                        if ((ASN1_STRING_to_UTF8(&cstring, str)) < 0)
                        {
                                WLog_ERR(TAG, "ASN1_STRING_to_UTF8() failed for GEN_EMAIL: %s",
                                        ERR_error_string(ERR_get_error(), NULL));
                                break;
                        }
                        else
                        {
                                WLog_ERR(TAG, "Adding KPN entry: %s", result);
                                result = strdup((char *)cstring);
                                break;
                        }
		}
	}
	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	return result;
}

/*
* Extract Certificate's Kerberos Principal Name
*/

static char * kpn_extractor(ASN1_TYPE * value)
{
        unsigned char* result = 0;
        ASN1_STRING* str = value->value.asn1_string;
        if ((ASN1_STRING_to_UTF8(&result, str)) < 0)
        {
                WLog_ERR(TAG, "ASN1_STRING_to_UTF8() failed for KPN_EXTRACTOR: %s",
                        ERR_error_string(ERR_get_error(), NULL));
                return 0;
        }
        else
        {
                WLog_ERR(TAG, "Adding KPN entry: %s", result);
                return strdup((char *)result);
        }
}

static x509_cert_info_t* cert_info_kpn(X509* x509)
{
        x509_cert_info_t* result;
	ASN1_OBJECT* krb5PrincipalName = OBJ_txt2obj("1.3.6.1.5.2.2", 1);
        char *  kpn = cert_info_get_othername(x509, krb5PrincipalName, kpn_extractor);
        if (!kpn)
        {
                return 0;
        }
        if (!(result = x509_cert_info_alloc(1)))
        {
                return 0;
        }
        result->entries[0] = kpn;
        result->count = 1;
        return result;
}

/*
* Extract Certificate's Microsoft Universal Principal Name
*/

static char * upn_extractor(ASN1_TYPE * value)
{
        if (value->type == V_ASN1_UTF8STRING)
        {
                ASN1_UTF8STRING* str = value->value.utf8string;
                WLog_DBG(TAG, "Adding UPN NAME entry= %s", str->data);
                return strdup((const char*)str->data);
        }
        else
        {
                WLog_ERR(TAG, "Found UPN entry is not an utf8string");
                return 0;
        }
}

static x509_cert_info_t* cert_info_upn(X509* x509)
{
        x509_cert_info_t* result;
	ASN1_OBJECT* msUPN = OBJ_nid2obj(NID_ms_upn);
        char * upn = cert_info_get_othername(x509, msUPN, upn_extractor);
        if (!upn)
        {
                return 0;
        }
        if (!(result = x509_cert_info_alloc(1)))
        {
                return 0;
        }
        result->entries[0] = upn;
        result->count = 1;
        return result;
}

static x509_cert_info_t* cert_info_email(X509* x509)
{
        x509_cert_info_t* result;
        char * email = cert_info_get_email(x509);
        if (!email)
        {
                return 0;
        }
        if (!(result = x509_cert_info_alloc(1)))
        {
                return 0;
        }
        result->entries[0] = email;
        result->count = 1;
        return result;
}

/*
* Return certificate key algorithm
*/
/* static x509_cert_info_t* cert_key_alg(X509* x509) */
/* { */
/* 	x509_cert_info_t* result; */
/* 	const char* alg = OBJ_nid2ln(OBJ_obj2nid(x509->cert_info->key->algor->algorithm)); */
/*         if (!(result = x509_cert_info_alloc(1))) */
/* 	{ */
/* 		return 0; */
/* 	} */
/*         result->entries[0] = strdup(alg); */
/*         result->count = 1; */
/* 	return result; */
/* } */

/**
* Request info on certificate.
* @param x509 	Certificate to parse.
* @param type 	Information to retrieve.
* @return x509_cert_info_t* with provided information.
*/
x509_cert_info_t* x509_cert_info(X509* x509, CERT_INFO_TYPE type)
{
	if (!x509)
	{
		WLog_WARN(TAG, "x509_cert_info: Null certificate provided.");
		return NULL;
	}

	switch (type)
	{
            case CERT_CN:
                    return cert_info_cn(x509);

            case CERT_SUBJECT:
                    return cert_info_subject(x509);

            case CERT_ISSUER:
                    return cert_info_issuer(x509);

            case CERT_KPN:
                    return cert_info_kpn(x509);

            case CERT_EMAIL:
                    return cert_info_email(x509);

            case CERT_UPN:
                    return cert_info_upn(x509);

            /* case CERT_KEY_ALG: */
            /*         return cert_key_alg(x509); */

            default:
                    WLog_DBG(TAG, "Invalid info type requested: %d", type);
                    return NULL;
	}
}

char* x509_cert_info_string(X509* x509, CERT_INFO_TYPE type)
{
	x509_cert_info_t* info = x509_cert_info(x509, type);
	if (info)
	{
		if(info->count >= 1)
		{
			char *  result = strdup(info->entries[0]);
			x509_cert_info_free(info);
			return result;
		}
	}
	return NULL;
}

