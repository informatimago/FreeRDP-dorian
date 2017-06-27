/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Heimdal Kerberos authentication for smartcard (PKINIT)
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

#ifndef PKINIT_HEIMDAL_H
#define PKINIT_HEIMDAL_H

#include <freerdp/types.h>
#include <freerdp/settings.h>
#include <freerdp/log.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

//#define HANDLE_PINPAD_WITH_LOGIN_REQUIRED

#include <heimdal/gssapi.h>
#include <heimdal/krb5.h>
#include <heimdal/getarg.h>
//#include <heimdal/krb5_asn1.h>
#include <heimdal/parse_time.h>
#include <heimdal/kafs.h>
#include "hx509.h"

#define _GNU_SOURCE
#include <stdio.h> /* asprintf */

#include <errno.h>
#include <locale.h>

#ifdef LIBINTL
#include <libintl.h>
#define N_(x,y) gettext(x)
#define NP_(x,y) (x)
#define getarg_i18n gettext
#else
#define N_(x,y) (x)
#define NP_(x,y) (x)
#define getarg_i18n NULL
#define bindtextdomain(package, localedir)
#define textdomain(package)
#endif

//#include <krb5/clpreauth_plugin.h>
#include <pkcs11-helper-1.0/pkcs11.h>

typedef struct _kerberos_settings{
	krb5_error_code ret;
	krb5_context context;
	krb5_principal principal;
	char * address;
	krb5_ccache ccache;
	krb5_init_creds_context ctx;
	krb5_creds * creds;
	krb5_get_init_creds_opt * options;
	void * data;
	char * identity;
	UINT32 freeRDP_error;
}kerberos_settings;

typedef struct _pkinit_anchors{
	size_t length;
	char * anchor;
}pkinit_anchors;

#define TERMSRV_SPN_PREFIX	"TERMSRV/"

typedef enum { INIT_CREDS_PINPAD, INIT_CREDS_KEYBOARD } action_type;

struct hx509_keyset_ops {
    const char *name;
    int flags;
    int (*init)(hx509_context, hx509_certs, void **,
                int, const char *, hx509_lock);
    int (*store)(hx509_context, hx509_certs, void *, int, hx509_lock);
    int (*free)(hx509_certs, void *);
    int (*add)(hx509_context, hx509_certs, void *, hx509_cert);
    int (*query)(hx509_context, hx509_certs, void *,
                 const hx509_query *, hx509_cert *);
    int (*iter_start)(hx509_context, hx509_certs, void *, void **);
    int (*iter)(hx509_context, hx509_certs, void *, void *, hx509_cert *);
    int (*iter_end)(hx509_context, hx509_certs, void *, void *);
    int (*printinfo)(hx509_context, hx509_certs,
                     void *, int (*)(void *, const char *), void *);
    int (*getkeys)(hx509_context, hx509_certs, void *, hx509_private_key **);
    int (*addkey)(hx509_context, hx509_certs, void *, hx509_private_key);
};

struct hx509_certs_data {
    unsigned int ref;
    struct hx509_keyset_ops *ops;
    void *ops_data;
};

typedef struct _k_opts
{
	int forwardable_flag;
	int proxiable_flag;
	int renewable_flag;
	int renew_flag;
	int pac_flag;
	int validate_flag;
	int version_flag;
	int help_flag;
	int addrs_flag;
	struct getarg_strings extra_addresses;
	int anonymous_flag;
	char *lifetime_s;
	char *renew_life;
	char *server_str;
	char *cred_cache;
	char *start_str;
	int switch_cache_flags;
	struct getarg_strings etype_str;
	int use_keytab;
	char *keytab_str;
	krb5_keytab kt;
	int do_afslog;
	int fcache_version;
	char *password_file;
	char *pk_user_id;
	int pk_enterprise_flag;
	struct hx509_certs_data *ent_user_id;
	char *pk_x509_anchors;
	int pk_use_enckey;
	int canonicalize_flag;
	int enterprise_flag;
	int ok_as_delegate_flag;
	char *fast_armor_cache_string;
	int use_referrals_flag;
	int windows_flag;


	// my variables
	/* in seconds */
	krb5_deltat starttime;
	krb5_deltat lifetime;
	krb5_deltat rlife;

//	int forwardable;
//	int proxiable;
//	int anonymous;
//	int addresses;

//	int not_forwardable;
//	int not_proxiable;
//	int no_addresses;

	int verbose;

	char* principal_name;
	char *domain;
	char* service_name;
//	char* keytab_name;
	char* k5_in_cache_name;
	char* k5_out_cache_name;
	char *armor_ccache;
	pkinit_anchors ** pkinit_anchors;

	action_type action;
//	int use_client_keytab;

//	int num_pa_opts;
//	krb5_gic_opt_pa_data *pa_opts;

//	int canonicalize;
//	int enterprise;

	krb5_data * outdata;

}k_opts;

struct k5_data
{
	krb5_context ctx;
	krb5_ccache in_cc, out_cc;
	krb5_principal me;
	char* name;
	krb5_boolean switch_to_cache;
};

BOOL pkinit_acquire_krb5_TGT(rdpSettings * settings);
BOOL get_TGT_kerberos(rdpSettings * settings);
BOOL set_pkinit_identity(rdpSettings * settings);
pkinit_anchors ** parse_pkinit_anchors(char * list_pkinit_anchors);
//int add_preauth_opt(k_opts *opts, char *av);
int k5_begin(k_opts* opts, struct k5_data* k5, rdpSettings * rdpSettings);
int k5_kinit(k_opts* opts, struct k5_data* k5, rdpSettings * rdpSettings);
void k5_end(struct k5_data* k5);
BOOL init_cred_cache(rdpSettings * settings);

krb5_error_code KRB5_CALLCONV krb5_copy_data_add0(krb5_context context, const krb5_data *indata, krb5_data **outdata);
krb5_error_code krb5int_copy_data_contents_add0(krb5_context context, const krb5_data *indata, krb5_data *outdata);
//void trace_callback(krb5_context context, const krb5_trace_info * info, void *cb);

#endif /* PKINIT_HEIMDAL_H */
