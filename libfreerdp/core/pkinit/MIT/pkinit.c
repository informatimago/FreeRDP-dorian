/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP MIT Kerberos authentication for smartcard (PKINIT)
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

#include <errno.h>
#include <freerdp/error.h>

#include "krb5.h"
#include "pkinit.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include </home/pjb/src/public/FreeRDP-devtools/krb5/print.h>
#include </home/pjb/src/public/FreeRDP-devtools/krb5/print.c>
//  char* string_concatenate(const char* string, ...);

#define TAG FREERDP_TAG("core.pkinit")

static const char* PREFIX_X509_ANCHORS = "X509_anchors=";
static const char* PREFIX_PKINIT_FILE = "FILE:";
static const char* PREFIX_X509_USER_IDENTITY = "X509_user_identity=";
static const char* PREFIX_PKINIT_PKCS11 = "PKCS11:module_name=";
static const char* PREFIX_PKINIT_CERT_ID = ":certid=";

static const char* PREFIX_PKINIT_CHALLENGE = KRB5_RESPONDER_QUESTION_PKINIT;
static const char* PREFIX_PKINIT_PKCS11_FORMAT_CHALLENGE = "={\"PKCS11:module_name=";
static const char* PREFIX_PKINIT_SLOT_ID = ":slotid=";
static const char* PREFIX_PKINIT_TOKEN_LABEL = ":token=";
static const char* SUFFIX_PKINIT_TOKEN_LABEL = "\":";
static const char* SUFFIX_PKINIT_FORMAT_CHALLENGE = "}";

/* Copy a data structure, with fresh allocation. */
krb5_error_code KRB5_CALLCONV
krb5_copy_data_add0(krb5_context context, const krb5_data* indata, krb5_data** outdata)
{
	krb5_data* tempdata;
	krb5_error_code retval;

	if (!indata)
	{
		*outdata = 0;
		return 0;
	}

	if (!(tempdata = (krb5_data*)malloc(sizeof(*tempdata))))
		return ENOMEM;

	retval = krb5int_copy_data_contents_add0(context, indata, tempdata);

	if (retval)
	{
		krb5_free_data_contents(context, tempdata);
		return retval;
	}

	*outdata = tempdata;
	return 0;
}

krb5_error_code
krb5int_copy_data_contents_add0(krb5_context context, const krb5_data* indata, krb5_data* outdata)
{
	if (!indata)
	{
		return EINVAL;
	}

	outdata->length = indata->length;

	if (outdata->length)
	{
		if (!(outdata->data = malloc(outdata->length + 1)))
		{
			return ENOMEM;
		}

		memcpy((char*)outdata->data, (char*)indata->data, outdata->length);
		outdata->data[outdata->length] = '\0';
	}
	else
		outdata->data = 0;

	outdata->magic = KV5M_DATA;
	return 0;
}

void trace_callback(krb5_context context, const krb5_trace_info* info, void* cb)
{
	if (info)
		WLog_INFO(TAG, "Kerberos : %s", info->message);
}

static char* progname = "pkinit";

#ifndef HAVE_PWD_H
#include <pwd.h>
static char* get_name_from_os()
{
	struct passwd* pw;

	if ((pw = getpwuid((int) getuid())))
	{
		return strdup(pw->pw_name);
	}

	return 0;
}
#else /* HAVE_PWD_H */
static char* get_name_from_os()
{
	return 0;
}
#endif


static krb5_context errctx;
static void extended_com_err_fn(const char* myprog, errcode_t code,
                                const char* fmt, va_list args)
{
	const char* emsg;
	emsg = krb5_get_error_message(errctx, code);
	fprintf(stderr, "%s: %s ", myprog, emsg);
	krb5_free_error_message(errctx, emsg);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}


BOOL set_pkinit_identity(rdpSettings* settings)
{
	settings->PkinitIdentity = string_concatenate(PREFIX_X509_USER_IDENTITY,
		PREFIX_PKINIT_PKCS11,
		settings->Pkcs11Module,
		PREFIX_PKINIT_SLOT_ID,
		settings->SlotID,
		PREFIX_PKINIT_TOKEN_LABEL,
		settings->TokenLabel,
		PREFIX_PKINIT_CERT_ID,
		settings->IdCertificate,
		NULL);

	if (!settings->PkinitIdentity)
	{
		WLog_ERR(TAG, "Error allocation settings Pkinit Identity");
		return FALSE;
	}

	WLog_DBG(TAG, "pkinit_identities = %s", settings->PkinitIdentity);
	return TRUE;
}


BOOL parse_pkinit_anchors(struct k_opts* opts, char* list_pkinit_anchors)
{
	WLog_DBG(TAG, "pkinit anchors : %s", list_pkinit_anchors);
	int i = 0, j = 0, nb_anchors = 0;
	opts->pkinit_anchors = (pkinit_anchors**) calloc(1, sizeof(pkinit_anchors*));

	if (opts->pkinit_anchors == NULL)
		return FALSE;

	char* pch;
	pch = strtok(list_pkinit_anchors, ",");

	if (pch == NULL)
	{
		free(opts->pkinit_anchors);
		return FALSE;
	}

	while (pch != NULL)
	{
		nb_anchors++;
		opts->pkinit_anchors[i] = (pkinit_anchors*) calloc(1, sizeof(pkinit_anchors));

		if (opts->pkinit_anchors[i] == NULL)
		{
			WLog_ERR(TAG, "Error memory allocation");
			goto get_error;
		}

		opts->pkinit_anchors[i]->anchor = _strdup(pch);

		if (opts->pkinit_anchors[i]->anchor == NULL)
		{
			WLog_ERR(TAG, "Error _strdup");
			goto get_error;
		}

		opts->pkinit_anchors[i]->length = strlen(opts->pkinit_anchors[i]->anchor);
		size_t new_size_array_anchors = strlen(opts->pkinit_anchors[i]->anchor) + strlen(
		                                    PREFIX_X509_ANCHORS) + strlen(PREFIX_PKINIT_FILE);
		opts->pkinit_anchors[i]->anchor = realloc(opts->pkinit_anchors[i]->anchor,
		                                  new_size_array_anchors + 1);

		if (opts->pkinit_anchors[i]->anchor == NULL)
		{
			WLog_ERR(TAG, "Error memory allocation");
			goto get_error;
		}

		memmove(opts->pkinit_anchors[i]->anchor + strlen(PREFIX_X509_ANCHORS) + strlen(PREFIX_PKINIT_FILE),
		        opts->pkinit_anchors[i]->anchor, opts->pkinit_anchors[i]->length + 1);
		memcpy(opts->pkinit_anchors[i]->anchor + 0, PREFIX_X509_ANCHORS, strlen(PREFIX_X509_ANCHORS));
		memcpy(opts->pkinit_anchors[i]->anchor + strlen(PREFIX_X509_ANCHORS), PREFIX_PKINIT_FILE,
		       strlen(PREFIX_PKINIT_FILE));
		*(opts->pkinit_anchors[i]->anchor + new_size_array_anchors) = '\0';
		pch = strtok(NULL, ",");

		if (pch != NULL)
		{
			opts->pkinit_anchors = (pkinit_anchors**) realloc(opts->pkinit_anchors,
			                       (nb_anchors + 1) * sizeof(pkinit_anchors*));

			if (opts->pkinit_anchors == NULL)
			{
				WLog_ERR(TAG, "Error memory allocation");
				goto get_error;
			}
		}

		i++;
	}

	/* if one or more pkinit anchors have been found return TRUE, otherwise FALSE */
	if (i)
	{
		opts->nb_anchors = nb_anchors;
		return TRUE;
	}

get_error:
	j = i + 1;

	while (j > 0)
	{
		free(opts->pkinit_anchors[j - 1]->anchor);
		j--;
	}

	while (j < nb_anchors)
	{
		free(opts->pkinit_anchors[j]);
		j++;
	}

	return FALSE;
}


static const char* integer_to_string_token_flags_responder(INT32 tokenFlags)
{
	static char token_flags_pkinit_formatted[2];
	/* Kerberos responder pkinit flags not applicable or no PIN error while logging */
	token_flags_pkinit_formatted[0] = '0' + (tokenFlags & 7);
	token_flags_pkinit_formatted[1] = 0;
	WLog_DBG(TAG, "%s %d : formatted pkinit token flags = %s", __FILENAME__, __LINE__,
	         token_flags_pkinit_formatted);
	return token_flags_pkinit_formatted;
}


void free_responder_data(responder_data* response)
{
	if ((*response)!= NULL)
	{
		free((*response)->challenge);
		(*response)->challenge = NULL;
		free((*response)->pkinit_answer);
		(*response)->pkinit_answer = NULL;
		free((*response));
		(*response) = NULL;
	}
}



BOOL init_responder_data(rdpSettings* settings, responder_data response)
{
	/* Check that a particular question has a specific challenge */
	response->challenge = string_concatenate(PREFIX_PKINIT_CHALLENGE,
		PREFIX_PKINIT_PKCS11_FORMAT_CHALLENGE,
		settings->Pkcs11Module,
		PREFIX_PKINIT_SLOT_ID,
		settings->SlotID,
		PREFIX_PKINIT_TOKEN_LABEL,
		settings->TokenLabel,
		SUFFIX_PKINIT_TOKEN_LABEL,
		integer_to_string_token_flags_responder(settings->TokenFlags),
		SUFFIX_PKINIT_FORMAT_CHALLENGE,
		NULL);

	if (response->challenge == NULL)
	{
		WLog_ERR(TAG, "Error allocation data challenge");
		goto get_error;
	}

	/* Set a PKINIT answer for a specific PKINIT identity. */
	response->pkinit_answer = string_concatenate(PREFIX_PKINIT_PKCS11,
		settings->Pkcs11Module,
		PREFIX_PKINIT_SLOT_ID,
		settings->SlotID,
		PREFIX_PKINIT_TOKEN_LABEL,
		settings->TokenLabel,
		"=",
		settings->Pin,
		NULL);

	if (response->pkinit_answer == NULL)
	{
		WLog_ERR(TAG, "Error allocation pkinit answer");
		goto get_error;
	}

	WLog_DBG(TAG, "pkinit_identities = %s", response->pkinit_answer);
	return TRUE;
get_error:
	free_responder_data(&response);
	return FALSE;
}


int add_preauth_opt(struct k_opts* opts, char* av)
{
	char* sep, *v;
	krb5_gic_opt_pa_data* p, *x;

	if (opts->num_pa_opts == 0)
	{
		opts->pa_opts = malloc(sizeof(krb5_gic_opt_pa_data));

		if (opts->pa_opts == NULL)
			return ENOMEM;
	}
	else
	{
		size_t newsize = (opts->num_pa_opts + 1) * sizeof(krb5_gic_opt_pa_data);
		x = realloc(opts->pa_opts, newsize);

		if (x == NULL)
		{
			free(opts->pa_opts);
			opts->pa_opts = NULL;
			return ENOMEM;
		}

		opts->pa_opts = x;
	}

	p = &opts->pa_opts[opts->num_pa_opts];
	sep = strchr(av, '=');

	if (sep)
	{
		*sep = '\0';
		v = ++sep;
		p->value = v;
	}
	else
	{
		p->value = "yes";
	}

	p->attr = av;
	opts->num_pa_opts++;
	return 0;
}



static BOOL string_list_contains(const char *const * list, const char * string)
{
	int i;
	for (i = 0;list[i];i ++ )
	{
		if (0 == strcmp(list[i], string))
		{
			return TRUE;
		}
	}
	return FALSE;
}

static krb5_error_code responder_dump_questions(krb5_context context, void *data, krb5_responder_context rctx)
{
	const char *const * questions = krb5_responder_list_questions(context, rctx);
	int i;
	for (i = 0;questions[i];i ++ )
	{
		printf("question: %s\n", questions[i]);
	}
	return KRB5KRB_ERR_GENERIC;
}

static krb5_error_code responder(krb5_context ctx, void* rawdata, krb5_responder_context rctx)
{
	krb5_error_code err;
	char* key, *value, *pin, *encoded1, *encoded2;
	const char* challenge;
	k5_json_value decoded1, decoded2;
	k5_json_object ids;
	k5_json_number val;
	krb5_int32 token_flags;
	responder_data data = rawdata;
	krb5_responder_pkinit_challenge* chl;
	krb5_responder_otp_challenge* ochl;
	unsigned int i, n;
	data->called = TRUE;

	WLog_INFO(TAG, "PKINIT responder");
	responder_dump_questions(ctx, rawdata, rctx);

	if (!rawdata)
	{
		WLog_ERR(TAG, "No responder data for responder");
		return 0;
	}

	WLog_INFO(TAG, "*krb5_responder_list_questions(ctx, rctx) = %s", *krb5_responder_list_questions(ctx, rctx));

	if (!string_list_contains(krb5_responder_list_questions(ctx, rctx), "pkinit"))
	{
		WLog_ERR(TAG, "No PKINIT question available");
		return 0;
	}

	/* Check that a particular challenge has the specified expected value. */
	if (data->challenge != NULL)
	{
		/* Separate the challenge name and its expected value. */
		key = strdup(data->challenge);

		if (key == NULL)
			return ENOMEM;

		value = key + strcspn(key, "=");

		if (*value != '\0')
			*value++ = '\0';

		/* Read the challenge. */
		challenge = krb5_responder_get_challenge(ctx, rctx, key);
		err = k5_json_decode(value, &decoded1);

		/* Check for "no challenge". */
		if (challenge == NULL && *value == '\0')
		{
			WLog_ERR(TAG, "OK: (no challenge) == (no challenge)");
		}
		else if (err != 0)
		{
			/* It's not JSON, so assume we're just after a string compare. */
			if (strcmp(challenge, value) == 0)
			{
				WLog_ERR(TAG, "OK: \"%s\" == \"%s\" ", challenge, value);
			}
			else
			{
				WLog_ERR(TAG, "ERROR: \"%s\" != \"%s\" ", challenge, value);
				return -1;
			}
		}
		else
		{
			/* Assume we're after a JSON compare - decode the actual value. */
			err = k5_json_decode(challenge, &decoded2);

			if (err != 0)
			{
				WLog_ERR(TAG, "error decoding \"%s\" ", challenge);
				return -1;
			}

			/* Re-encode the expected challenge and the actual challenge... */
			err = k5_json_encode(decoded1, &encoded1);

			if (err != 0)
			{
				WLog_ERR(TAG, "error encoding json data");
				return -1;
			}

			err = k5_json_encode(decoded2, &encoded2);

			if (err != 0)
			{
				WLog_ERR(TAG, "error encoding json data");
				return -1;
			}

			k5_json_release(decoded1);
			k5_json_release(decoded2);

			/* ... and see if they look the same. */
			if (strcmp(encoded1, encoded2) == 0)
			{
				WLog_DBG(TAG, "OK: \"%s\" == \"%s\"\n", encoded1, encoded2);
			}
			else
			{
				WLog_ERR(TAG, "ERROR: \"%s\" != \"%s\" ", encoded1,
				         encoded2);
				return -1;
			}

			free(encoded1);
			free(encoded2);
		}

		free(key);
	}

	/* Provide a particular response for a challenge. */
	if (data->response != NULL)
	{
		/* Separate the challenge and its data content... */
		key = strdup(data->response);

		if (key == NULL)
			return ENOMEM;

		value = key + strcspn(key, "=");

		if (*value != '\0')
			*value++ = '\0';

		/* ... and pass it in. */
		err = krb5_responder_set_answer(ctx, rctx, key, value);

		if (err != 0)
		{
			WLog_ERR(TAG, "error setting response");
			return -1;
		}

		free(key);
	}

	if (data->print_pkinit_challenge)
	{
		/* Read the PKINIT challenge, formatted as a structure. */
		err = krb5_responder_pkinit_get_challenge(ctx, rctx, &chl);

		if (err != 0)
		{
			WLog_ERR(TAG, "error getting pkinit challenge");
			return -1;
		}

		if (chl != NULL)
		{
			for (n = 0; chl->identities[n] != NULL; n++)
				continue;

			for (i = 0; chl->identities[i] != NULL; i++)
			{
				if (chl->identities[i]->token_flags != -1)
				{
					WLog_DBG(TAG, "identity %u/%u: %s (flags=0x%lx)\n", i + 1, n,
					         chl->identities[i]->identity,
					         (long)chl->identities[i]->token_flags);
				}
				else
				{
					WLog_DBG(TAG, "identity %u/%u: %s\n", i + 1, n,
					         chl->identities[i]->identity);
				}
			}
		}

		krb5_responder_pkinit_challenge_free(ctx, rctx, chl);
	}

	/* Provide a particular response for the PKINIT challenge. */
	if (data->pkinit_answer != NULL)
	{
		/* Read the PKINIT challenge, formatted as a structure. */
		err = krb5_responder_pkinit_get_challenge(ctx, rctx, &chl);

		if (err != 0)
		{
			WLog_ERR(TAG, "error getting pkinit challenge");
			return -1;
		}

		/*
		 * In case order matters, if the identity starts with "FILE:", exercise
		 * the set_answer function, with the real answer second.
		 */
		if (chl != NULL &&
		    chl->identities != NULL &&
		    chl->identities[0] != NULL)
		{
			if (strncmp(chl->identities[0]->identity, "FILE:", 5) == 0)
				krb5_responder_pkinit_set_answer(ctx, rctx, "foo", "bar");
		}

		/* Provide the real answer. */
		key = strdup(data->pkinit_answer);

		if (key == NULL)
			return ENOMEM;

		value = strrchr(key, '=');

		if (value != NULL)
			*value++ = '\0';
		else
			value = "";

		err = krb5_responder_pkinit_set_answer(ctx, rctx, key, value);

		if (err != 0)
		{
			WLog_ERR(TAG, "error setting response");
			return -1;
		}

		free(key);

		/*
		 * In case order matters, if the identity starts with "PKCS12:",
		 * exercise the set_answer function, with the real answer first.
		 */
		if (chl != NULL &&
		    chl->identities != NULL &&
		    chl->identities[0] != NULL)
		{
			if (strncmp(chl->identities[0]->identity, "PKCS12:", 7) == 0)
				krb5_responder_pkinit_set_answer(ctx, rctx, "foo", "bar");
		}

		krb5_responder_pkinit_challenge_free(ctx, rctx, chl);
	}

	/*
	 * Something we always check: read the PKINIT challenge, both as a
	 * structure and in JSON form, reconstruct the JSON form from the
	 * structure's contents, and check that they're the same.
	 */
	challenge = krb5_responder_get_challenge(ctx, rctx,
	            KRB5_RESPONDER_QUESTION_PKINIT);

	if (challenge != NULL)
	{
		krb5_responder_pkinit_get_challenge(ctx, rctx, &chl);

		if (chl == NULL)
		{
			WLog_ERR(TAG, "pkinit raw challenge set, "
			         "but structure is NULL");
			return -1;
		}

		if (k5_json_object_create(&ids) != 0)
		{
			WLog_ERR(TAG, "error creating json objects");
			return -1;
		}

		for (i = 0; chl->identities[i] != NULL; i++)
		{
			token_flags = chl->identities[i]->token_flags;

			if (k5_json_number_create(token_flags, &val) != 0)
			{
				WLog_ERR(TAG, "error creating json number");
				return -1;
			}

			if (k5_json_object_set(ids, chl->identities[i]->identity,
			                       val) != 0)
			{
				WLog_ERR(TAG, "error adding json number to object");
				return -1;
			}

			k5_json_release(val);
		}

		/* Encode the structure... */
		err = k5_json_encode(ids, &encoded1);

		if (err != 0)
		{
			WLog_ERR(TAG, "error encoding json data");
			return -1;
		}

		k5_json_release(ids);

		/* ... and see if they look the same. */
		if (strcmp(encoded1, challenge) != 0)
		{
			WLog_ERR(TAG, "\"%s\" != \"%s\" ", encoded1, challenge);
			return -1;
		}

		krb5_responder_pkinit_challenge_free(ctx, rctx, chl);
		free(encoded1);
	}

	/* Provide a particular response for an OTP challenge. */
	if (data->otp_answer != NULL)
	{
		if (krb5_responder_otp_get_challenge(ctx, rctx, &ochl) == 0)
		{
			key = strchr(data->otp_answer, '=');

			if (key != NULL)
			{
				/* Make a copy of the answer that we can chop up. */
				key = strdup(data->otp_answer);

				if (key == NULL)
					return ENOMEM;

				/* Isolate the ti value. */
				value = strchr(key, '=');
				*value++ = '\0';
				n = atoi(key);
				/* Break the value and PIN apart. */
				pin = strchr(value, ':');

				if (pin != NULL)
					*pin++ = '\0';

				err = krb5_responder_otp_set_answer(ctx, rctx, n, value, pin);

				if (err != 0)
				{
					WLog_ERR(TAG, "error setting response");
					return -1;
				}

				free(key);
			}

			krb5_responder_otp_challenge_free(ctx, rctx, ochl);
		}
	}

	return 0;
}

const char * k5_error_message(struct k5_data *  k5, int code)
{
	switch (code)
	{
		case KRB5KRB_AP_ERR_BAD_INTEGRITY:
			return "Password incorrect";
		case KRB5KDC_ERR_KEY_EXP:
			return "Password has expired";
		case KRB5KDC_ERR_PREAUTH_FAILED:
			return "Preauthentication failed";
		case KRB5KDC_ERR_POLICY:
			return "KDC policy rejects request";
		case KRB5KDC_ERR_BADOPTION:
			return "KDC can't fulfill requested option";
		case KRB5KDC_ERR_CLIENT_REVOKED:
			return "Client's credentials have been revoked";
		case KRB5KDC_ERR_SERVICE_REVOKED:
			return "Credentials for server have been revoked";
		case KRB5KDC_ERR_CANNOT_POSTDATE:
			return "Ticket is ineligible for postdating";
		case KRB5_RCACHE_BADVNO:
			return "Unsupported replay cache format version number";
		case KRB5_KDCREP_MODIFIED:
			return "KDC reply did not match expectations";
		case KRB5KRB_AP_ERR_TKT_NYV:
			return "Ticket not yet valid";
		case KRB5KRB_AP_ERR_SKEW:
			return "Clock skew too great";
		default:
			return krb5_get_error_message(k5->ctx, code);
	}
}



const char * k5_prompt_type_label(krb5_prompt_type type)
{
	switch (type)
	{
		case KRB5_PROMPT_TYPE_PASSWORD:            return "KRB5_PROMPT_TYPE_PASSWORD";
		case KRB5_PROMPT_TYPE_NEW_PASSWORD:        return "KRB5_PROMPT_TYPE_NEW_PASSWORD";
		case KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN:  return "KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN";
		case KRB5_PROMPT_TYPE_PREAUTH:             return "KRB5_PROMPT_TYPE_PREAUTH";
		default:                                   return "unknown";
	}
}

static krb5_error_code prompter_dump(krb5_context context, void *data, const char *name, const char *banner, int num_prompts, krb5_prompt prompts[])
{
	int i;
	// ck_token_flags_label
	// printf("context->prompt_type = (%d) %s\n", context->prompt_type, k5_prompt_type_label(context->prompt_type));
        printf("data                 = %p\n", data);
        printf("name        	     = %s\n", name);
        printf("banner      	     = %s\n", banner);
        printf("num_prompts 	     = %d\n", num_prompts);
        for (i = 0;i < num_prompts;i ++ )
	{
		printf("prompts[%d]           = [%s] %s\n", i, (prompts[i].hidden?"hidden":"visible"), prompts[i].prompt);
		if (prompts[i].reply)
		{
			if((prompts[i].reply->length) && (prompts[i].reply->data))
			{
				prompts[i].reply->data[0] = 0;
			}
		}
	}
	return 0;
	return KRB5KRB_ERR_GENERIC;
}

static void opts_log_pa_opts(struct k_opts * opts, const char *where)
{
	int i;
	WLog_DBG(TAG, "in %-30s Num PA Options = %d", where, opts->num_pa_opts);
	for (i = 0; i < opts->num_pa_opts; i++)
	{
		WLog_DBG(TAG, "in %-30s PA Option %s = %s ", where,  opts->pa_opts[i].attr, opts->pa_opts[i].value);
	}
}

static int opts_convert_to_options(krb5_context ctx, struct k_opts* opts, krb5_get_init_creds_opt** options)
{
	int i;
	int code = krb5_get_init_creds_opt_alloc(ctx, options);

	if (code)
	{
		goto cleanup;
	}

	if (opts->lifetime)
		krb5_get_init_creds_opt_set_tkt_life(*options, opts->lifetime);

	if (opts->rlife)
		krb5_get_init_creds_opt_set_renew_life(*options, opts->rlife);

	if (opts->forwardable)
		krb5_get_init_creds_opt_set_forwardable(*options, 1);

	if (opts->not_forwardable)
		krb5_get_init_creds_opt_set_forwardable(*options, 0);

	if (opts->proxiable)
		krb5_get_init_creds_opt_set_proxiable(*options, 1);

	if (opts->not_proxiable)
		krb5_get_init_creds_opt_set_proxiable(*options, 0);

	if (opts->canonicalize)
		krb5_get_init_creds_opt_set_canonicalize(*options, 1);

	if (opts->anonymous)
		krb5_get_init_creds_opt_set_anonymous(*options, 1);

	if (opts->addresses)
	{
		krb5_address** addresses = NULL;
		code = krb5_os_localaddr(ctx, &addresses);

		if (code != 0)
		{
			WLog_ERR(TAG, "%s : Error %d getting local addresses", progname, code);
			goto cleanup;
		}

		krb5_get_init_creds_opt_set_address_list(*options, addresses);
	}

	if (opts->no_addresses)
		krb5_get_init_creds_opt_set_address_list(*options, NULL);

	if (opts->armor_ccache)
		krb5_get_init_creds_opt_set_fast_ccache_name(ctx, *options, opts->armor_ccache);

	for (i = 0; i < opts->num_pa_opts; i++)
	{
		code = krb5_get_init_creds_opt_set_pa(ctx, *options,
			opts->pa_opts[i].attr,
			opts->pa_opts[i].value);

		if (code != 0)
		{
			WLog_ERR(TAG, "%s : Error %d while setting '%s'='%s'",
				progname, code, opts->pa_opts[i].attr, opts->pa_opts[i].value);
			goto cleanup;
		}
	}


	/*  Seems to be useless,  since krb actually stores PAs into hidden fields beyond the public struct declaration. */
	(*options)->preauth_list_length = 1;
	(*options)->preauth_list = malloc((*options)->preauth_list_length * sizeof ((*options)->preauth_list));
	*((*options)->preauth_list) = 16;

	opts_log_pa_opts(opts, __FUNCTION__);
	return 0;
cleanup:
	opts_log_pa_opts(opts, __FUNCTION__);
	return code;
}


static struct k_opts * opts_new()
{
	return calloc(1, sizeof (struct k_opts));
}

static void opts_free(struct k_opts * opts)
{
	int i;

	if (opts->pa_opts != NULL)
	{
		free(opts->pa_opts);
		opts->pa_opts = NULL;
	}

	opts->num_pa_opts = 0;

	if (opts->pkinit_anchors != NULL)
	{
		for (i = opts->nb_anchors; i > 0 ; i--)
		{
			free(opts->pkinit_anchors[i - 1]->anchor);
			opts->pkinit_anchors[i - 1]->anchor = NULL;
			free(opts->pkinit_anchors[i - 1]);
			opts->pkinit_anchors[i - 1] = NULL;
		}
	}

	free(opts->pkinit_anchors);
	opts->pkinit_anchors = NULL;
	free(opts->principal_name);
	opts->principal_name = NULL;
	free(opts);
}


int k5_kinit(struct k_opts* opts, struct k5_data* k5, responder_data response,
             rdpSettings* settings)
{
	int notix = 1;
	int i = 0;
	krb5_creds* my_creds = NULL;
	krb5_error_code code = 0;
	krb5_get_init_creds_opt* options = NULL;
	BOOL pinPadMode = settings->PinPadIsPresent;
	BOOL loginRequired = settings->PinLoginRequired;
	char* doing = 0;

	my_creds = calloc(1, sizeof(* my_creds));

	if (!my_creds)
	{
		goto cleanup;
	}

	code = opts_convert_to_options(k5->ctx, opts, & options);

	if (code)
	{
		goto cleanup;
	}

	if (k5->in_cc)
	{
		code = krb5_get_init_creds_opt_set_in_ccache(k5->ctx, options, k5->in_cc);

		if (code)
		{
			goto cleanup;
		}
	}

	code = krb5_get_init_creds_opt_set_out_ccache(k5->ctx, options, k5->out_cc);
	if (code)
	{
		goto cleanup;
	}

	{
		char * soptions = sprint_krb5_get_init_creds_opt(options);
		WLog_DBG(TAG, "%s : options: %s", progname, soptions);
		free(soptions);
	}

	if (pinPadMode && !loginRequired)
	{
		opts->action = INIT_CREDS_PINPAD;
		doing = "getting initial credentials with pinpad";
	}
	else if (!pinPadMode)
	{
		opts->action = INIT_CREDS_KEYBOARD;
		doing = "getting initial credentials with keyboard or command line";
	}

#ifdef HANDLE_PINPAD_WITH_LOGIN_REQUIRED
	else if (pinPadMode && loginRequired)
	{
		opts->action = INIT_CREDS_PINPAD;
		doing = "getting initial credentials with pinpad (login required)";
	}

#endif

	switch (opts->action)
	{
		case INIT_CREDS_PINPAD:

			code = krb5_get_init_creds_opt_set_responder(k5->ctx, options, responder /* responder_dump_questions */ , response);

			if (code)
			{
				WLog_ERR(TAG, "%s : Error while setting responder: %s", progname, error_message(code));
				goto cleanup;
			}

			code = krb5_get_init_creds_password(k5->ctx,
				my_creds,
				/* client principal: */ k5->me,
				/* password: */ 0,
				/* prompter: */ 0, /* prompter_dump, */
				/* promter_data: */ 0,
				opts->starttime,
				opts->service_name,
				options);
			break;

		case INIT_CREDS_KEYBOARD:
			code = krb5_get_init_creds_opt_set_responder(k5->ctx, options,
			        responder_dump_questions, response);

			if (code)
			{
				WLog_ERR(TAG, "%s : Error while setting responder: %s", progname, error_message(code));
				goto cleanup;
			}

			code = krb5_get_init_creds_password(k5->ctx,
				my_creds,
				/* client principal: */ k5->me,
				/* password: */ 0,
				/* prompter: */ 0,
				/* promter_data: */ 0,
				opts->starttime,
				opts->service_name,
				options);

			if (!response->called)
			{
				WLog_ERR(TAG, "%s : Responder callback wasn't called", progname);
				goto cleanup;
			}

			break;
	}

	if (code)
	{
		WLog_ERR(TAG, "%s: %s while %s", progname, k5_error_message(k5, code), doing);
		goto cleanup;
	}

	/* Conditional validation of the credentials obtained if KDC is able to perform it */
	if (opts->starttime)
	{
		code = krb5_get_validated_creds(k5->ctx, my_creds, k5->me, k5->out_cc,
		                                opts->service_name);

		if (code)
		{
			WLog_ERR(TAG, "%s : Error %d while validating credentials : %s",
				progname, code, k5_error_message(k5, code));
			goto cleanup;
		}

		code = krb5_cc_initialize(k5->ctx, k5->out_cc, opts->canonicalize ?
		                          my_creds->client : k5->me);

		if (code)
		{
			WLog_ERR(TAG, "%s : Error %d when initializing cache %s", progname,
			         code, opts->k5_out_cache_name ? opts->k5_out_cache_name : "");
			goto cleanup;
		}

		WLog_DBG(TAG, "%s : Initialized cache", progname);
		code = krb5_cc_store_cred(k5->ctx, k5->out_cc, my_creds);

		if (code)
		{
			WLog_ERR(TAG, "%s : Error %d while storing credentials", progname, code);
			goto cleanup;
		}

		WLog_DBG(TAG, "%s : Stored credentials", progname);
	}

	/* Get canonicalized principal name for credentials delegation (CredSSP) */
	krb5_copy_data_add0(k5->ctx, my_creds->client->data, &(opts->outdata));
	notix = 0;

	if (k5->switch_to_cache)
	{
		code = krb5_cc_switch(k5->ctx, k5->out_cc);

		if (code)
		{
			WLog_ERR(TAG, "%s : Error %d while switching to new ccache", progname, code);
			goto cleanup;
		}
	}

cleanup:

	if (options)
	{
		krb5_get_init_creds_opt_free(k5->ctx, options);
	}

	if (my_creds)
	{
		if (my_creds->client == k5->me)
		{
			my_creds->client = 0;
		}

		krb5_free_cred_contents(k5->ctx, my_creds);
		free(my_creds);
		my_creds = NULL;
	}

	if (opts->pa_opts != NULL)
	{
		free(opts->pa_opts);
		opts->pa_opts = NULL;
	}

	opts->num_pa_opts = 0;

	if (opts->pkinit_anchors)
	{
		for (i = opts->nb_anchors; i > 0 ; i--)
		{
			free(opts->pkinit_anchors[i - 1]->anchor);
			opts->pkinit_anchors[i - 1]->anchor = NULL;
			free(opts->pkinit_anchors[i - 1]);
			opts->pkinit_anchors[i - 1] = NULL;
		}
	}

	free(opts->pkinit_anchors);
	opts->pkinit_anchors = NULL;
	return notix ? 0 : 1; /* return 0 if error, 1 otherwise */
}

static BOOL split_name_from_realm_in_principal_name(char * name, char ** domain)
{
	/* get back domain in settings if not specified in command line */
	/*  TODO: WHY DO WE CUT IT OFF k5->name IN THAT CASE??? */
	if (*domain == NULL)
	{
		char* find_domain = strrchr(name, '@');

		if (find_domain != NULL)
		{
			*find_domain++ = '\0';
			*domain = strdup(find_domain);

			if (!(*domain))
			{
				WLog_ERR(TAG, "Error allocation domain");
				return FALSE;
			}
		}
		else
		{
			WLog_ERR(TAG, "Error getting back domain");
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL resolve_output_cache(struct k_opts* opts, struct k5_data* k5)
{
	int code = krb5_cc_resolve(k5->ctx, opts->k5_out_cache_name, &k5->out_cc);
	if (code != 0)
	{
		WLog_ERR(TAG, "%s : Error %d resolving ccache %s", progname, code, opts->k5_out_cache_name);
		return FALSE;
	}

	WLog_DBG(TAG, "%s : Using specified cache: %s", progname, opts->k5_out_cache_name);
	return TRUE;
}

typedef struct
{
	krb5_ccache cache;
	krb5_principal principal;
	const char* type;
	char* realm;
} default_cache_t;

static BOOL resolve_default_cache(struct k_opts* opts, struct k5_data* k5,
	default_cache_t * defcache)
{

	/* Resolve the default ccache and get its type and default principal
	* (if it is initialized). */
	int code = krb5_cc_default(k5->ctx, & (defcache->cache));

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d while getting default ccache", progname, code);
		return FALSE;
	}

	defcache->type = krb5_cc_get_type(k5->ctx, defcache->cache);

	if (krb5_cc_get_principal(k5->ctx, defcache->cache, &(defcache->principal)) != 0)
	{
		defcache->principal = NULL;
	}

	WLog_DBG(TAG, "%s : Using default cache", progname);
	return TRUE;
}

static BOOL use_principal_name(struct k_opts* opts, struct k5_data* k5, int flags,
	char * principal_name, krb5_principal *  principal)
{
	/* Use the specified principal name. */
	int code = krb5_parse_name_flags(k5->ctx, principal_name, flags, principal);

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d when parsing name %s", progname, code, principal_name);
		return FALSE;
	}

	{
		char * sprincipal = sprint_krb5_principal(* principal);
		WLog_DBG(TAG, "%s : Using principal name: %s principal: %s", progname,  principal_name, sprincipal);
		free(sprincipal);
	}
	return TRUE;
}


#define LENGTH_AND_STRING(string) strlen(string), string
static BOOL use_anonymous_principal(struct k_opts* opts, struct k5_data* k5, int flags, default_cache_t * defcache,
	char * principal_name, krb5_principal *  principal)
{

	int code = krb5_get_default_realm(k5->ctx, &(defcache->realm));

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d while getting default realm", progname, code);
		return FALSE;
	}

	code = krb5_build_principal_ext(k5->ctx, principal,
		LENGTH_AND_STRING(defcache->realm),
		LENGTH_AND_STRING(KRB5_WELLKNOWN_NAMESTR),
		LENGTH_AND_STRING(KRB5_ANONYMOUS_PRINCSTR),
		0);

	krb5_free_default_realm(k5->ctx, defcache->realm);
	defcache->realm = NULL;

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d while building principal", progname, code);
		return FALSE;
	}

	{
		char * sprincipal = sprint_krb5_principal(* principal);
		WLog_DBG(TAG, "%s : Using principal name: %s principal: %s", progname,  principal_name, sprincipal);
		free(sprincipal);
	}
	return TRUE;
}

static BOOL use_cached_principal(struct k_opts* opts, struct k5_data* k5, int flags,
	krb5_principal *  principal)
{
	krb5_principal result;

	if (krb5_cc_get_principal(k5->ctx, k5->out_cc, & result) == 0)
	{
		(*principal) = result;
	}

	{
		char * sprincipal = sprint_krb5_principal(* principal);
		WLog_DBG(TAG, "%s : Using cached principal: %s", progname, sprincipal);
		free(sprincipal);
	}
	return TRUE;
}

static BOOL use_default_principal(struct k_opts* opts, struct k5_data* k5, int flags, default_cache_t * defcache,
	krb5_principal *  principal)
{
	/* Use the default cache's principal, and use the default cache as the output cache. */
	k5->out_cc = defcache->cache;
	defcache->cache = NULL;
	(*principal) = defcache->principal;
	defcache->principal = NULL;
	/* { */
	/* 	char * sprincipal = sprint_krb5_principal(* principal); */
	/* 	WLog_DBG(TAG, "%s : Using default principal: %s", progname, sprincipal); */
	/* 	free(sprincipal); */
	/* } */
	return TRUE;
}

static BOOL use_local_username(struct k_opts* opts, struct k5_data* k5, int flags,
	krb5_principal *  principal)
{
	char * name = get_name_from_os();

	if (name == NULL)
	{
		WLog_ERR(TAG, "%s : Unable to identify user", progname);
		return FALSE;
	}

	int code = krb5_parse_name_flags(k5->ctx, name, flags, principal);

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d when parsing name %s", progname, code, name);
		free(name);
		return FALSE;
	}

	/* { */
	/* 	char * sprincipal = sprint_krb5_principal(* principal); */
	/* 	WLog_DBG(TAG, "%s : Using local user name: %s principal: %s", progname, name, sprincipal); */
	/* 	free(sprincipal); */
	/* } */

	free(name);
	return TRUE;
}

static BOOL regenerate_cache(struct k_opts* opts, struct k5_data* k5, default_cache_t * defcache)
{
	/* Use an existing cache for the client principal if we can. */
	int code = krb5_cc_cache_match(k5->ctx, k5->me, &k5->out_cc);

	if ((code != 0) && (code != KRB5_CC_NOTFOUND))
	{
		WLog_ERR(TAG, "%s : Error %d while searching for ccache for %s", progname, code, k5->name);
		return FALSE;
	}

	if (code == 0)
	{
		WLog_DBG(TAG, "Using existing cache: %s", krb5_cc_get_name(k5->ctx, k5->out_cc));
		k5->switch_to_cache = 1;
	}
	else if (defcache->principal != NULL)
	{
		/* Create a new cache to avoid overwriting the initialized default
		* cache. */
		code = krb5_cc_new_unique(k5->ctx, defcache->type, NULL, &k5->out_cc);

		if (code)
		{
			WLog_ERR(TAG, "%s : Error %d while generating new ccache", progname, code);
			return FALSE;
		}

		WLog_DBG(TAG, "Using new cache: %s", krb5_cc_get_name(k5->ctx, k5->out_cc));
		k5->switch_to_cache = 1;
	}
	return TRUE;
}


BOOL k5_begin(struct k_opts* opts, struct k5_data* k5, rdpSettings* settings)
{
	krb5_error_code code = 0;
	BOOL success = FALSE;
	int i = 0;
	int anchors_init = 1;
	default_cache_t defcache = {NULL, NULL, NULL, NULL};
	char* pkinit_identity = settings->PkinitIdentity;
	char* list_pkinit_anchors = settings->PkinitAnchors;
	memset(k5, 0, sizeof(* k5));
	/* set opts */
	opts->lifetime = settings->LifeTime;
	opts->rlife = settings->RenewableLifeTime;
	opts->forwardable = 1;
	opts->not_forwardable = 0;
	opts->canonicalize = 1; /* Canonicalized UPN is required for credentials delegation (CredSSP) */
	int flags = opts->enterprise ? KRB5_PRINCIPAL_PARSE_ENTERPRISE : 0;
	/* set pkinit identities */
	if (add_preauth_opt(opts, pkinit_identity))
	{
		WLog_ERR(TAG, "%s : Error while setting pkinit identities", progname);
		goto cleanup;
	}

	/* set pkinit anchors */
	if (list_pkinit_anchors == NULL || (list_pkinit_anchors != NULL &&
	                                    (strlen(list_pkinit_anchors) == 0)))
	{
		WLog_WARN(TAG, "%s : /pkinit-anchors missing.  Will retrieve anchors via krb5.conf", progname);
	}
	else
	{
		if (parse_pkinit_anchors(opts, list_pkinit_anchors) == FALSE)
		{
			WLog_ERR(TAG, "%s : Fail to get pkinit anchors", progname);
			goto cleanup;
		}

		while (i < opts->nb_anchors && opts->pkinit_anchors && opts->pkinit_anchors[i]->anchor)
		{
			anchors_init = add_preauth_opt(opts, opts->pkinit_anchors[i]->anchor);

			if (anchors_init != 0)
			{
				WLog_ERR(TAG, "%s : Error while setting pkinit anchors", progname);
				goto cleanup;
			}

			i++;
		}
	}

	code = krb5_init_context(&k5->ctx);

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d while initializing Kerberos 5 library", progname, code);
		goto cleanup;
	}

	errctx = k5->ctx;

	/* make KRB5 PKINIT verbose */
	if (settings->Krb5Trace)
	{
		WLog_INFO(TAG, "%s : Krb5 trace activated", progname);
		int ret = krb5_set_trace_callback(k5->ctx, &trace_callback, NULL);

		if (ret == KRB5_TRACE_NOSUPP)
		{
			WLog_ERR(TAG, "%s : KRB5_TRACE_NOSUPP", __FUNCTION__);
		}
	}

	WLog_DBG(TAG, "Cache selection");
	if (opts->k5_out_cache_name)
	{
		success = resolve_output_cache(opts, k5);
	}
	else
	{
		success = resolve_default_cache(opts, k5, & defcache);
	}

	if (!success)
	{
		goto cleanup;
	}


	/* Choose a client principal name. */
	success = TRUE;
	if (opts->principal_name != NULL)
	{
		success = use_principal_name(opts, k5, flags, opts->principal_name, & k5->me);
	}
	else if (opts->anonymous)
	{
		success = use_anonymous_principal(opts, k5, flags, & defcache, opts->principal_name, & k5->me);
	}
	else if (k5->out_cc != NULL)
	{
		success = use_cached_principal(opts, k5, flags, & k5->me);
	}
	else if (defcache.principal != NULL)
	{
		success = use_default_principal(opts, k5, flags, & defcache, & k5->me);
	}

	if (!success)
	{
		goto cleanup;
	}

	/* If we still haven't chosen, use the local username. */
	if (k5->me == NULL)
	{
		if (!(success = use_local_username(opts, k5, flags, & k5->me)))
		{
			goto cleanup;
		}
	}

	if (k5->out_cc == NULL && krb5_cc_support_switch(k5->ctx, defcache.type))
	{
		if(!(success = regenerate_cache(opts, k5, & defcache)))
		{
			goto cleanup;
		}
	}

	/* Use the default cache if we haven't picked one yet. */
	if (k5->out_cc == NULL)
	{
		k5->out_cc = defcache.cache;
		defcache.cache = NULL;
		WLog_DBG(TAG, "Using default cache: %s",
		         krb5_cc_get_name(k5->ctx, k5->out_cc));
	}

	if (opts->k5_in_cache_name)
	{
		code = krb5_cc_resolve(k5->ctx, opts->k5_in_cache_name, &k5->in_cc);

		if (code != 0)
		{
			WLog_ERR(TAG, "%s : Error %d resolving ccache %s",
			         progname, code, opts->k5_in_cache_name);
			goto cleanup;
		}

		WLog_DBG(TAG, "Using specified input cache: %s",
		         opts->k5_in_cache_name);
	}


	free(k5->name);
	/* free before krb5_unparse_name change its address */
	code = krb5_unparse_name(k5->ctx, k5->me, &k5->name);

	if (code)
	{
		WLog_ERR(TAG, "%s : Error %d when unparsing name", progname, code);
		goto cleanup;
	}

 /* PJB: k5->me done ==> k5->name */

	WLog_DBG(TAG, "Using principal name    : %s", k5->name);

	if (split_name_from_realm_in_principal_name(k5->name, & settings->Domain))
	{
		WLog_DBG(TAG, "Split principal name    : %s", k5->name);
		WLog_DBG(TAG, "Domain / Kerberos realm : %s", settings->Domain);
	}
	else
	{
		goto cleanup;
	}

	success = TRUE;

cleanup:

	if (defcache.cache != NULL)
		krb5_cc_close(k5->ctx, defcache.cache);

	krb5_free_principal(k5->ctx, defcache.principal);
	return success;
}


void k5_end(struct k5_data* k5)
{
	if (k5->name)
		krb5_free_unparsed_name(k5->ctx, k5->name);

	if (k5->me)
		krb5_free_principal(k5->ctx, k5->me);

	if (k5->in_cc)
		krb5_cc_close(k5->ctx, k5->in_cc);

	if (k5->out_cc)
		krb5_cc_close(k5->ctx, k5->out_cc);

	if (k5->ctx)
		krb5_free_context(k5->ctx);

	errctx = NULL;
	memset(k5, 0, sizeof(*k5));
}


BOOL initialize_credential_cache(rdpSettings* settings, struct k_opts *  opts)
{
	BOOL at = (NULL != strchr(settings->UserPrincipalName, '@'));
	memset(opts, 0, sizeof(* opts));
	opts->principal_name = strdup(settings->UserPrincipalName);

	if (opts->principal_name == NULL)
	{
		WLog_ERR(TAG, "Could not allocate principal name.");
		return FALSE;
	}

	if (at)
	{
		opts->enterprise = KRB5_PRINCIPAL_PARSE_ENTERPRISE;
	}

	/* if /d:domain is specified in command line, set it as Kerberos default realm */
	if (!at && settings->Domain)
	{
		WLog_DBG(TAG, "opts->principal_name = %s", opts->principal_name);
		WLog_DBG(TAG, "settings->Domain     = %s", settings->Domain);
		opts->principal_name = realloc(opts->principal_name, strlen(opts->principal_name) + 1 + strlen(settings->Domain) + 1);

		if (opts->principal_name == NULL)
		{
			WLog_ERR(TAG, "Could not reallocate principal name.");
			free(opts->principal_name);
			return FALSE;
		}

		strcat(opts->principal_name, "@");
		strcat(opts->principal_name, settings->Domain);
		WLog_DBG(TAG, "opts->principal_name = %s", opts->principal_name);
	}


	/* Start time is the time when ticket (TGT) issued by the KDC become valid.
	 * It needs to be different from 0 to request a postdated ticket.
	 * And thus, enable validation of credentials by the KDC, that can only validate postdated ticket */
	opts->starttime = settings->StartTime;

	return TRUE;
}

BOOL new_responder_data(rdpSettings* settings, responder_data *  response)
{
	(*response) = calloc(1, sizeof(**response));

	if ((*response) == NULL)
	{
		WLog_ERR(TAG, "Error allocation responder data.");
		return FALSE;
	}

	if (!init_responder_data(settings, *response))
	{
		free_responder_data(response);
		return FALSE;
	}
	return TRUE;
}



/** pkinit_acquire_krb5_TGT is used to acquire credentials via Kerberos.
 *  This function is actually called in get_TGT_kerberos().
 *  @param krb_settings - pointer to the kerberos_settings structure
 *  @return TRUE if valid TGT acquired, FALSE otherwise
 */
BOOL pkinit_acquire_krb5_TGT(rdpSettings* settings)
{
	struct k_opts *  opts = opts_new();
	struct k5_data  k5;
	responder_data  response = 0;
	BOOL authed_k5 = FALSE;
	set_com_err_hook(extended_com_err_fn);
	if (set_pkinit_identity(settings)
		&& initialize_credential_cache(settings, opts)
		/* set data responder callback if no PINPAD present: */
		&& (0 != strncmp(settings->Pin, "NULL", 4) || new_responder_data(settings, &response))
		&& k5_begin(opts, &k5, settings))
	{
		opts_log_pa_opts(opts, __FUNCTION__);
		authed_k5 = k5_kinit(opts, &k5, response, settings);
	}
	if (authed_k5 && opts->outdata->data)
	{
		settings->CanonicalizedUserHint = strdup(opts->outdata->data);
		if (settings->CanonicalizedUserHint == NULL)
		{
			WLog_ERR(TAG, "Error cannot strdup outdata into canonicalized user hint.");
			authed_k5 = FALSE;
		}

		krb5_free_data(k5.ctx, opts->outdata);
	}
	else
	{
		WLog_ERR(TAG, "authed_k5 but no opts->outdata->data! No canonicalized user hint!");
	}

	k5_end(&k5);
	free_responder_data(&response);
	opts_free(opts);
	opts = 0;

	if (authed_k5)
	{
		WLog_INFO(TAG, "Authenticated to Kerberos v5 via smartcard");
	}
	else
	{
		WLog_ERR(TAG, "Credentials cache initialization failed !");
	}

	return authed_k5;
}

/** get_TGT_kerberos is used to get TGT from KDC.
 *  This function is actually called in nla_client_init().
 *  @param settings - pointer to rdpSettings structure that contains the settings
 *  @return TRUE if the Kerberos negotiation was successful.
 */
BOOL get_TGT_kerberos(rdpSettings* settings)
{
	if (!pkinit_acquire_krb5_TGT(settings))
	{
		return FALSE;
	}

	WLog_DBG(TAG, "Successfully acquired Kerberos TGT");
	return TRUE;
}
