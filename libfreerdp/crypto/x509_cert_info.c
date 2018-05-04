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

#include <freerdp/crypto/crypto.h>

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


#define countof(a) (sizeof (a) / sizeof (a[0]))
static const char * seps[] =
 // { "C = ", ", ST = ", ", L = ", ", O = ", ", OU = ", ", CN = "};
{ "C = ", ", O = ", ", OU = ", ", OU = ", ", UID = ", ", GN = ", ", SN = ", ", CN = "};

static char*  x509_name_to_utf8_string(X509_NAME* name)
{
	int count;
	struct
	{
		char* string;
		int length;
	} * temp;
	int total_length = 0;
	const char* sep;
        const char* default_sep = "; ";
	int seplen;
	int loc;
	count = X509_NAME_entry_count(name);

	if (count == 0)
	{
		return strdup("");
	}

	temp = malloc(sizeof(*temp) * count);

	if (!temp)
	{
		return 0;
	}

	/* collect entry strings,  and compute total length */
	for (loc = 0; loc < count; loc ++)
	{
                seplen = seps[loc]?strlen(seps[loc]):strlen(default_sep);
		temp[loc].string = x509_name_entry_to_utf8_string(name, loc);

		if (temp[loc].string)
		{
			temp[loc].length = strlen(temp[loc].string);
			total_length += seplen + temp[loc].length;
		}
		else
		{
			temp[loc].length = 0;
		}
	}

	char* result = malloc(total_length + 1);

	if (result)
	{
                int pos;
		for (pos = 0, loc = 0; loc < count; loc ++)
		{
                        sep = seps[loc]?seps[loc]:default_sep;
                        seplen = strlen(sep);
                        
			strncpy(result + pos, sep, seplen);
			pos += seplen;

			if (temp[loc].string)
			{
				strncpy(result + pos, temp[loc].string, temp[loc].length);
				pos += temp[loc].length;
			}
		}

		result[pos] = 0;
	}

	for (loc = 0; loc < count; loc ++)
	{
		free(temp[loc].string);
	}

	free(temp);
	return result;
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


/*
* Extract Certificate's Kerberos Principal Name
*/
static x509_cert_info_t* cert_info_kpn(X509* x509)
{
        int i, j;
	STACK_OF(GENERAL_NAME) *gens;
	GENERAL_NAME* name;
	ASN1_OBJECT* krb5PrincipalName;
	x509_cert_info_t* result;
        if (!(result = x509_cert_info_alloc(1)))
	{
		return 0;
	}
	WLog_DBG(TAG, "Trying to find a Kerberos Principal Name in certificate");
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	krb5PrincipalName = OBJ_txt2obj("1.3.6.1.5.2.2", 1);

	if (!gens)
	{
		WLog_ERR(TAG, "No alternate name extensions");
                goto fail;
	}

	if (!krb5PrincipalName)
	{
		WLog_ERR(TAG, "Cannot map KPN object");
                goto fail;
	}

	for (i = 0, j = 0; (i < sk_GENERAL_NAME_num(gens)) && (j < CERT_INFO_MAX_ENTRIES); i++)
	{
		name = sk_GENERAL_NAME_value(gens, i);

		if (name && name->type == GEN_OTHERNAME)    /* test for UPN */
		{
			WLog_ERR(TAG, "GEN_OTHERNAME");

			if (OBJ_cmp(name->d.otherName->type_id, krb5PrincipalName))
			{
				WLog_ERR(TAG, "krb5PrincipalName");
				continue; /* object is not a UPN */
			}
			else
			{
				/* NOTE:
				from PKINIT RFC, I deduce that stored format for kerberos
				Principal Name is ASN1_STRING, but not sure at 100%
				Any help will be granted
				*/
				unsigned char* txt;
				ASN1_TYPE* val = name->d.otherName->value;
				ASN1_STRING* str = val->value.asn1_string;
				WLog_DBG(TAG, "Found Kerberos Principal Name ");

				if ((ASN1_STRING_to_UTF8(&txt, str)) < 0)
				{
					WLog_ERR(TAG, "ASN1_STRING_to_UTF8() failed: %s", ERR_error_string(ERR_get_error(), NULL));
				}
				else
				{
					WLog_ERR(TAG, "Adding KPN entry: %s", txt);
					result->entries[j++] = strdup((const char*)txt);
				}
			}
		}
	}

	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
	ASN1_OBJECT_free(krb5PrincipalName);

	if (j == 0)
	{
		WLog_ERR(TAG, "Certificate does not contain a KPN entry");
                goto fail;
	}

	WLog_ERR(TAG, "end of cert_info_kpn\n");
        result->count = j;
	return result;
fail:
        x509_cert_info_free(result);
        return NULL;
}

/*
* Extract Certificate's Microsoft Universal Principal Name
*/
static x509_cert_info_t* cert_info_upn(X509* x509)
{
	int i, j;
	STACK_OF(GENERAL_NAME) *gens;
	GENERAL_NAME* name;
	x509_cert_info_t* result;
        if (!(result = x509_cert_info_alloc(1)))
	{
		return 0;
	}
	WLog_DBG(TAG, "Trying to find an Universal Principal Name in certificate");
	gens = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);

	if (!gens)
	{
		WLog_ERR(TAG, "No alternate name extensions found");
		goto fail;
	}

	for (i = 0, j = 0; (i < sk_GENERAL_NAME_num(gens)) && (j < CERT_INFO_MAX_ENTRIES); i++)
	{
		name = sk_GENERAL_NAME_value(gens, i);

		if (name && name->type == GEN_OTHERNAME)
		{
			/* test for UPN */
			if (OBJ_cmp(name->d.otherName->type_id,
			            OBJ_nid2obj(NID_ms_upn))) continue; /* object is not a UPN */

			WLog_DBG(TAG, "Found Microsoft Universal Principal Name ");

			/* try to extract string and return it */
			if (name->d.otherName->value->type == V_ASN1_UTF8STRING)
			{
				ASN1_UTF8STRING* str = name->d.otherName->value->value.utf8string;
				WLog_DBG(TAG, "Adding UPN NAME entry= %s", str->data);
				result->entries[j++] = strdup((const char*)str->data);
			}
			else
			{
				WLog_ERR(TAG, "Found UPN entry is not an utf8string");
			}
		}
	}

	sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

	if (j == 0)
	{
		WLog_ERR(TAG, "Certificate does not contain a Microsoft UPN entry");
		goto fail;
	}

        result->count = j;
	return result;
fail:
        x509_cert_info_free(result);
        return NULL;
}

/*
* Return certificate key algorithm
*/
static x509_cert_info_t* cert_key_alg(X509* x509)
{
	x509_cert_info_t* result;
	const char* alg = OBJ_nid2ln(OBJ_obj2nid(x509->cert_info->key->algor->algorithm));
        if (!(result = x509_cert_info_alloc(1)))
	{
		return 0;
	}
        result->entries[0] = strdup(alg);
        result->count = 1;
	return result;
}

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
		case CERT_CN		:
			return cert_info_cn(x509);

		case CERT_SUBJECT	:
			return cert_info_subject(x509);

		case CERT_ISSUER	:
			return cert_info_issuer(x509);

		case CERT_KPN		:
			return cert_info_kpn(x509);

		case CERT_UPN		:
			return cert_info_upn(x509);

		case CERT_KEY_ALG	:
			return cert_key_alg(x509);

		default           :
			WLog_DBG(TAG, "Invalid info type requested: %d", type);
			return NULL;
	}
}
