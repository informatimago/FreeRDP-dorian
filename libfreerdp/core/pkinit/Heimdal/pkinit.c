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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef COUCOU

//#include "kuser_locl.h"
//#include "kuser_locl.h"

#include "pkinit.h"
//#include <errno.h>
//#include <heimdal/getarg.h>
//#include <locale.h>
//#include <heimdal/krb5_asn1.h>

#include <openssl/ui.h>
#include <err.h>

//#include <heimdal/krb5.h>
//#include <heimdal/krb5-protos.h>

#define TAG FREERDP_TAG("core.pkinit")
#define PKINIT_ANCHORS_MAX 10

static char *progname = "Heimdal-Pkinit";

static const char * PREFIX_X509_ANCHORS = "-D ";
static const char * PREFIX_PKINIT_FILE = "FILE:";
static const char * PREFIX_X509_USER_IDENTITY = "X509_user_identity=";
static const char * PREFIX_PKINIT_PKCS11 = "PKCS11:";
static const char * PREFIX_PKINIT_CERT_ID = ":certid=";

#ifndef SIGINFO
#define SIGINFO SIGUSR1
#endif


#ifdef args
static struct getargs args[] = {
    /*
     * used by MIT
     * a: ~A
     * V: verbose
     * F: ~f
     * P: ~p
     * C: v4 cache name?
     * 5:
     *
     * old flags
     * 4:
     * 9:
     */
    { "afslog", 	0  , arg_flag, &do_afslog,
      NP_("obtain afs tokens", ""), NULL },

    { "cache", 		'c', arg_string, &cred_cache,
      NP_("credentials cache", ""), "cachename" },

    { "forwardable",	'F', arg_negative_flag, &forwardable_flag,
      NP_("get tickets not forwardable", ""), NULL },

    { NULL,		'f', arg_flag, &forwardable_flag,
      NP_("get forwardable tickets", ""), NULL },

    { "lifetime",	'l', arg_string, &lifetime_s,
      NP_("lifetime of tickets", ""), "time" },

    { "proxiable",	'p', arg_flag, &proxiable_flag,
      NP_("get proxiable tickets", ""), NULL },

    { "renew",          'R', arg_flag, &renew_flag,
      NP_("renew TGT", ""), NULL },

    { "renewable",	0,   arg_flag, &renewable_flag,
      NP_("get renewable tickets", ""), NULL },

    { "renewable-life",	'r', arg_string, &renew_life,
      NP_("renewable lifetime of tickets", ""), "time" },

    { "server", 	'S', arg_string, &server_str,
      NP_("server to get ticket for", ""), "principal" },

    { "start-time",	's', arg_string, &start_str,
      NP_("when ticket gets valid", ""), "time" },

    { "validate",	'v', arg_flag, &validate_flag,
      NP_("validate TGT", ""), NULL },

    { "enctypes",	'e', arg_strings, &etype_str,
      NP_("encryption types to use", ""), "enctypes" },

    { "fcache-version", 0,   arg_integer, &fcache_version,
      NP_("file cache version to create", ""), NULL },

    { "addresses",	'A',   arg_negative_flag,	&addrs_flag,
      NP_("request a ticket with no addresses", ""), NULL },

    { "extra-addresses",'a', arg_strings,	&extra_addresses,
      NP_("include these extra addresses", ""), "addresses" },

    { "request-pac",	0,   arg_flag,	&pac_flag,
      NP_("request a Windows PAC", ""), NULL },

    { "password-file",	0,   arg_string, &password_file,
      NP_("read the password from a file", ""), NULL },

    { "canonicalize",0,   arg_flag, &canonicalize_flag,
      NP_("canonicalize client principal", ""), NULL },

    { "enterprise",0,   arg_flag, &enterprise_flag,
      NP_("parse principal as a KRB5-NT-ENTERPRISE name", ""), NULL },
#ifdef PKINIT
    { "pk-enterprise",	0,	arg_flag,	&pk_enterprise_flag,
      NP_("use enterprise name from certificate", ""), NULL },

    { "pk-user",	'C',	arg_string,	&pk_user_id,
      NP_("principal's public/private/certificate identifier", ""), "id" },

    { "x509-anchors",	'D',  arg_string, &pk_x509_anchors,
      NP_("directory with CA certificates", ""), "directory" },

    { "pk-use-enckey",	0,  arg_flag, &pk_use_enckey,
      NP_("Use RSA encrypted reply (instead of DH)", ""), NULL },
#endif

    { "change-default",  0,  arg_negative_flag, &switch_cache_flags,
      NP_("switch the default cache to the new credentials cache", ""), NULL },

    { "ok-as-delegate",	0,  arg_flag, &ok_as_delegate_flag,
      NP_("honor ok-as-delegate on tickets", ""), NULL },

    { "fast-armor-cache",	0,  arg_string, &fast_armor_cache_string,
      NP_("use this credential cache as FAST armor cache", ""), "cache" },

    { "use-referrals",	0,  arg_flag, &use_referrals_flag,
      NP_("only use referrals, no dns canalisation", ""), NULL },

    { "windows",	0,  arg_flag, &windows_flag,
      NP_("get windows behavior", ""), NULL },

    { "version", 	0,   arg_flag, &version_flag, NULL, NULL },
    { "help",		0,   arg_flag, &help_flag, NULL, NULL }
};
#endif // args





BOOL set_pkinit_identity(rdpSettings * settings)
{
	unsigned int size_PkinitIdentity = strlen(PREFIX_X509_USER_IDENTITY) + strlen(PREFIX_PKINIT_PKCS11) + strlen(settings->Pkcs11Module) + strlen(PREFIX_PKINIT_CERT_ID) + (unsigned int) (settings->IdCertificateLength * 2);
	settings->PkinitIdentity = calloc( size_PkinitIdentity + 1, sizeof(char) );
	if( !settings->PkinitIdentity ){
		WLog_ERR(TAG, "Error allocation settings Pkinit Identity");
		return FALSE;
	}

	strncat(settings->PkinitIdentity, PREFIX_X509_USER_IDENTITY, strlen(PREFIX_X509_USER_IDENTITY) );
	strncat(settings->PkinitIdentity, PREFIX_PKINIT_PKCS11, strlen(PREFIX_PKINIT_PKCS11) );
	strncat(settings->PkinitIdentity, settings->Pkcs11Module, strlen(settings->Pkcs11Module) );
	strncat(settings->PkinitIdentity, PREFIX_PKINIT_CERT_ID, strlen(PREFIX_PKINIT_CERT_ID) );
	strncat(settings->PkinitIdentity, (char*) settings->IdCertificate, (unsigned int) (settings->IdCertificateLength * 2) );

	settings->PkinitIdentity[size_PkinitIdentity] = '\0';

	return TRUE;
}


pkinit_anchors ** parse_pkinit_anchors(char * list_pkinit_anchors)
{
	pkinit_anchors ** array_pkinit_anchors = NULL;
	array_pkinit_anchors = (pkinit_anchors**) calloc( PKINIT_ANCHORS_MAX, sizeof(pkinit_anchors *));
	if(array_pkinit_anchors == NULL)
		return NULL;

	int i=0, j=0;
	for(i=0; i<PKINIT_ANCHORS_MAX; i++){
		array_pkinit_anchors[i] = (pkinit_anchors*) calloc( 1, sizeof(pkinit_anchors));
		if(array_pkinit_anchors[i] == NULL){
			while(i){
				free(array_pkinit_anchors[i-1]);
				i--;
			}
			free(array_pkinit_anchors);
			return NULL;
		}
	}

	WLog_DBG(TAG, "list pkinit anchors : %s", list_pkinit_anchors);

	char * pch;
	pch = strtok (list_pkinit_anchors,",");

	if(pch==NULL){
		for(i=0; i<PKINIT_ANCHORS_MAX; i++)
			free(array_pkinit_anchors[i]);
		free(array_pkinit_anchors);
		return NULL;
	}

	i=0;

	while (pch != NULL)
	{
		array_pkinit_anchors[i]->anchor = _strdup( pch );

		if( array_pkinit_anchors[i]->anchor == NULL ){
			WLog_ERR(TAG, "Error _strdup");
			j = i + 1;
			while(j > 0){
				free(array_pkinit_anchors[j-1]->anchor);
				j--;
			}
			while(j < PKINIT_ANCHORS_MAX){
				free(array_pkinit_anchors[j]);
				j++;
			}
			free(array_pkinit_anchors);
			return NULL;
		}

		array_pkinit_anchors[i]->length = strlen( array_pkinit_anchors[i]->anchor );
		size_t new_size_array_anchors = strlen( array_pkinit_anchors[i]->anchor ) + strlen(PREFIX_X509_ANCHORS) + strlen(PREFIX_PKINIT_FILE);

		array_pkinit_anchors[i]->anchor = realloc( array_pkinit_anchors[i]->anchor, new_size_array_anchors + 1);
		if( array_pkinit_anchors[i]->anchor == NULL) {
			j = i + 1;
			while(j > 0){
				free(array_pkinit_anchors[j-1]->anchor);
				j--;
			}
			while(j < PKINIT_ANCHORS_MAX){
				free(array_pkinit_anchors[j]);
				j++;
			}
			free(array_pkinit_anchors);
			return NULL;
		}

		memmove( array_pkinit_anchors[i]->anchor + strlen(PREFIX_X509_ANCHORS) + strlen(PREFIX_PKINIT_FILE), array_pkinit_anchors[i]->anchor, array_pkinit_anchors[i]->length + 1);
		memcpy( array_pkinit_anchors[i]->anchor + 0, PREFIX_X509_ANCHORS, strlen(PREFIX_X509_ANCHORS) );
		memcpy( array_pkinit_anchors[i]->anchor + strlen(PREFIX_X509_ANCHORS), PREFIX_PKINIT_FILE, strlen(PREFIX_PKINIT_FILE) );

		*(array_pkinit_anchors[i]->anchor + new_size_array_anchors) = '\0';

		pch = strtok (NULL, ",");

		i++;

		if( pch != NULL && i == PKINIT_ANCHORS_MAX ){
			WLog_ERR(TAG, "Error : too much anchors given");
			for( i=PKINIT_ANCHORS_MAX; i>0 ; i-- )
				free(array_pkinit_anchors[i-1]->anchor);
			free(array_pkinit_anchors);
			return NULL;
		}
	}

	if(i)
		return array_pkinit_anchors;
	else{
		free(array_pkinit_anchors);
		return NULL;
	}
}

/*
int add_preauth_opt(struct k_opts *opts, char *av)
{
	char *sep, *v;
	krb5_gic_opt_pa_data *p, *x;

	if (opts->num_pa_opts == 0) {
		opts->pa_opts = malloc(sizeof(krb5_gic_opt_pa_data));
		if (opts->pa_opts == NULL)
			return ENOMEM;
	} else {
		size_t newsize = (opts->num_pa_opts + 1) * sizeof(krb5_gic_opt_pa_data);
		x = realloc(opts->pa_opts, newsize);
		if (x == NULL){
			free(opts->pa_opts);
			opts->pa_opts = NULL;
			return ENOMEM;
		}
		opts->pa_opts = x;
	}
	p = &opts->pa_opts[opts->num_pa_opts];
	sep = strchr(av, '=');
	if (sep) {
		*sep = '\0';
		v = ++sep;
		p->value = v;
	} else {
		p->value = "yes";
	}
	p->attr = av;
	opts->num_pa_opts++;

	return 0;
}*/


static krb5_error_code
get_server(krb5_context context,
	   krb5_principal client,
	   const char *server,
	   krb5_principal *princ)
{
    krb5_const_realm realm;
    if (server)
	return krb5_parse_name(context, server, princ);

    realm = krb5_principal_get_realm(context, client);
    return krb5_make_principal(context, princ, realm,
			       KRB5_TGS_NAME, realm, NULL);
}

static krb5_error_code
copy_configs(krb5_context context,
	     krb5_ccache dst,
	     krb5_ccache src,
	     krb5_principal start_ticket_server)
{
    krb5_error_code ret;
    const char *cfg_names[] = {"realm-config", "FriendlyName", NULL};
    const char *cfg_names_w_pname[] = {"fast_avail", NULL};
    krb5_data cfg_data;
    size_t i;

    for (i = 0; cfg_names[i]; i++) {
	ret = krb5_cc_get_config(context, src, NULL, cfg_names[i], &cfg_data);
	if (ret == KRB5_CC_NOTFOUND || ret == KRB5_CC_END) {
	    continue;
	} else if (ret) {
	    krb5_warn(context, ret, "krb5_cc_get_config");
	    return ret;
	}
	ret = krb5_cc_set_config(context, dst, NULL, cfg_names[i], &cfg_data);
	if (ret)
	    krb5_warn(context, ret, "krb5_cc_set_config");
    }
    for (i = 0; start_ticket_server && cfg_names_w_pname[i]; i++) {
	ret = krb5_cc_get_config(context, src, start_ticket_server,
				 cfg_names_w_pname[i], &cfg_data);
	if (ret == KRB5_CC_NOTFOUND || ret == KRB5_CC_END) {
	    continue;
	} else if (ret) {
	    krb5_warn(context, ret, "krb5_cc_get_config");
	    return ret;
	}
	ret = krb5_cc_set_config(context, dst, start_ticket_server,
				 cfg_names_w_pname[i], &cfg_data);
	if (ret && ret != KRB5_CC_NOTFOUND)
	    krb5_warn(context, ret, "krb5_cc_set_config");
    }
    /*
     * We don't copy cc configs for any other principals though (mostly
     * those are per-target time offsets and the like, so it's bad to
     * lose them, but hardly the end of the world, and as they may not
     * expire anyways, it's good to let them go).
     */
    return 0;
}

static krb5_error_code
renew_validate(krb5_context context,
		   k_opts * opts,
	       int renew,
	       int validate,
	       krb5_ccache cache,
	       const char *server,
	       krb5_deltat life)
{
    krb5_error_code ret;
    krb5_ccache tempccache = NULL;
    krb5_creds in, *out = NULL;
    krb5_kdc_flags flags;

    memset(&in, 0, sizeof(in));

    ret = krb5_cc_get_principal(context, cache, &in.client);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_get_principal");
		return ret;
    }
    ret = get_server(context, in.client, server, &in.server);
    if (ret) {
		krb5_warn(context, ret, "get_server");
		goto out;
    }

    if (renew) {
		/*
		 * no need to check the error here, it's only to be
		 * friendly to the user
		 */
		krb5_get_credentials(context, KRB5_GC_CACHED, cache, &in, &out);
    }

    flags.i = 0;
    flags.b.renewable         = flags.b.renew = renew;
    flags.b.validate          = validate;

    if (opts->forwardable_flag != -1)
    	flags.b.forwardable       = opts->forwardable_flag;
    else if (out)
    	flags.b.forwardable 	  = out->flags.b.forwardable;

    if (opts->proxiable_flag != -1)
    	flags.b.proxiable         = opts->proxiable_flag;
    else if (out)
    	flags.b.proxiable 	  = out->flags.b.proxiable;

    if (opts->anonymous_flag)
    	flags.b.request_anonymous = opts->anonymous_flag;
    if (life)
    	in.times.endtime = time(NULL) + life;

    if (out) {
		krb5_free_creds(context, out);
		out = NULL;
    }

    ret = krb5_get_kdc_cred(context,
			    cache,
			    flags,
			    NULL,
			    NULL,
			    &in,
			    &out);
    if (ret) {
		krb5_warn(context, ret, "krb5_get_kdc_cred");
		goto out;
    }

    ret = krb5_cc_new_unique(context, krb5_cc_get_type(context, cache),
			     NULL, &tempccache);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_new_unique");
		goto out;
    }

    ret = krb5_cc_initialize(context, tempccache, in.client);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_initialize");
		goto out;
    }

    ret = krb5_cc_store_cred(context, tempccache, out);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_store_cred");
		goto out;
    }

    /*
     * We want to preserve cc configs as some are security-relevant, and
     * anyways it's the friendly thing to do.
     */
    ret = copy_configs(context, tempccache, cache, out->server);
    if (ret)
    	goto out;

    ret = krb5_cc_move(context, tempccache, cache);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_move");
		goto out;
    }
    tempccache = NULL;

out:
    if (tempccache)
    	krb5_cc_close(context, tempccache);
    if (out)
    	krb5_free_creds(context, out);
    krb5_free_cred_contents(context, &in);
    return ret;
}

static krb5_error_code
get_new_tickets(krb5_context context,
		krb5_principal principal,
		krb5_ccache ccache,
		krb5_deltat ticket_life,
		k_opts * opts,
		int interactive)
{
    krb5_error_code ret;
    krb5_creds cred;
    char passwd[256];
    krb5_deltat start_time = 0;
    krb5_deltat renew = 0;
    const char *renewstr = NULL;
    krb5_enctype *enctype = NULL;
    krb5_ccache tempccache = NULL;
    krb5_init_creds_context ctx = NULL;
    krb5_get_init_creds_opt *opt = NULL;
    krb5_prompter_fct prompter = krb5_prompter_posix;

    passwd[0] = '\0';

    if (!interactive)
    	prompter = NULL;

    if (opts->password_file) {
    	FILE *f;

		if (strcasecmp("STDIN", opts->password_file) == 0)
			f = stdin;
		else
			f = fopen(opts->password_file, "r");
		if (f == NULL) {
			krb5_warnx(context, "Failed to open the password file %s",
					opts->password_file);
			return errno;
		}

		if (fgets(passwd, sizeof(passwd), f) == NULL) {
			krb5_warnx(context, N_("Failed to read password from file %s", ""),
					opts->password_file);
			fclose(f);
			return EINVAL; /* XXX Need a better error */
		}
		if (f != stdin)
			fclose(f);
		passwd[strcspn(passwd, "\n")] = '\0';
    }

    memset(&cred, 0, sizeof(cred));

    ret = krb5_get_init_creds_opt_alloc(context, &opt);
    if (ret) {
		krb5_warn(context, ret, "krb5_get_init_creds_opt_alloc");
		goto out;
    }

    krb5_get_init_creds_opt_set_default_flags(context, "kinit",
	krb5_principal_get_realm(context, principal), opt);

    if (opts->forwardable_flag != -1)
    	krb5_get_init_creds_opt_set_forwardable(opt, opts->forwardable_flag);
    if (opts->proxiable_flag != -1)
    	krb5_get_init_creds_opt_set_proxiable(opt, opts->proxiable_flag);
    if (opts->anonymous_flag)
    	krb5_get_init_creds_opt_set_anonymous(opt, opts->anonymous_flag);
    if (opts->pac_flag != -1)
    	krb5_get_init_creds_opt_set_pac_request(context, opt,
			opts->pac_flag ? TRUE : FALSE);
    if (opts->canonicalize_flag)
    	krb5_get_init_creds_opt_set_canonicalize(context, opt, TRUE);
    if (opts->pk_enterprise_flag || opts->enterprise_flag || opts->canonicalize_flag || opts->windows_flag)
    	krb5_get_init_creds_opt_set_win2k(context, opt, TRUE);
    if (opts->pk_user_id || opts->ent_user_id || opts->anonymous_flag) {
    	ret = krb5_get_init_creds_opt_set_pkinit(context, opt,
							 principal,
							 opts->pk_user_id,
							 opts->pk_x509_anchors,
							 NULL,
							 NULL,
							 opts->pk_use_enckey ? 2 : 0 |
							 opts->anonymous_flag ? 4 : 0,
							 prompter,
							 NULL,
							 passwd);
		if (ret) {
			krb5_warn(context, ret, "krb5_get_init_creds_opt_set_pkinit");
			goto out;
		}
		if (opts->ent_user_id)
			krb5_get_init_creds_opt_set_pkinit_user_certs(context, opt, opts->ent_user_id);
    }

    if (opts->addrs_flag != -1)
    	krb5_get_init_creds_opt_set_addressless(context, opt,
			opts->addrs_flag ? FALSE : TRUE);

    if (opts->renew_life == NULL && opts->renewable_flag)
    	renewstr = "6 months";
    if (opts->renew_life)
    	renewstr = opts->renew_life;
    if (renewstr) {
    	renew = parse_time(renewstr, "s");
    	if (renew < 0)
    		errx(1, "unparsable time: %s", renewstr);

		krb5_get_init_creds_opt_set_renew_life(opt, renew);
    }

    if (ticket_life != 0)
    	krb5_get_init_creds_opt_set_tkt_life(opt, ticket_life);

    if (opts->start_str) {
    	int tmp = parse_time(opts->start_str, "s");
    	if (tmp < 0)
    		errx(1, N_("unparsable time: %s", ""), opts->start_str);

    	start_time = tmp;
    }

    if (opts->etype_str.num_strings) {
    	int i;

		enctype = malloc(opts->etype_str.num_strings * sizeof(*enctype));
		if (enctype == NULL)
			errx(1, "out of memory");
		for(i = 0; i < opts->etype_str.num_strings; i++) {
			ret = krb5_string_to_enctype(context,
					opts->etype_str.strings[i],
						 &enctype[i]);
			if (ret)
				errx(1, "unrecognized enctype: %s", opts->etype_str.strings[i]);
		}
		krb5_get_init_creds_opt_set_etype_list(opt, enctype,
				opts->etype_str.num_strings);
    }

    ret = krb5_init_creds_init(context, principal, prompter, NULL, start_time, opt, &ctx);
    if (ret) {
    	krb5_warn(context, ret, "krb5_init_creds_init");
    	goto out;
    }

    if (opts->server_str) {
    	ret = krb5_init_creds_set_service(context, ctx, opts->server_str);
		if (ret) {
			krb5_warn(context, ret, "krb5_init_creds_set_service");
			goto out;
		}
    }

    if (opts->fast_armor_cache_string) {
	krb5_ccache fastid;

	ret = krb5_cc_resolve(context, opts->fast_armor_cache_string, &fastid);
	if (ret) {
	    krb5_warn(context, ret, "krb5_cc_resolve(FAST cache)");
	    goto out;
	}

	ret = krb5_init_creds_set_fast_ccache(context, ctx, fastid);
	if (ret) {
	    krb5_warn(context, ret, "krb5_init_creds_set_fast_ccache");
	    goto out;
	}
    }

    if (opts->pk_user_id || opts->ent_user_id || opts->anonymous_flag) {

    } else if (!interactive && passwd[0] == '\0') {
		static int already_warned = 0;

		if (!already_warned)
			krb5_warnx(context, "Not interactive, failed to get "
			  "initial ticket");
		krb5_get_init_creds_opt_free(context, opt);
		already_warned = 1;
		return 0;
    } else {

		if (passwd[0] == '\0') {
			char *p, *prompt;
			int aret = 0;

			ret = krb5_unparse_name(context, principal, &p);
			if (ret)
				errx(1, "failed to generate passwd prompt: not enough memory");

			aret = asprintf(&prompt, N_("%s's Password: ", ""), p);
			free(p);
			if (aret == -1)
				errx(1, "failed to generate passwd prompt: not enough memory");

			if (UI_UTIL_read_pw_string(passwd, sizeof(passwd)-1, prompt, 0)){
				memset(passwd, 0, sizeof(passwd));
				errx(1, "failed to read password");
			}
			free(prompt);
		}

		if (passwd[0]) {
			ret = krb5_init_creds_set_password(context, ctx, passwd);
			if (ret) {
				krb5_warn(context, ret, "krb5_init_creds_set_password");
				goto out;
			}
		}
    }

    ret = krb5_init_creds_get(context, ctx);

    memset(passwd, 0, sizeof(passwd));

    switch(ret){
    case 0:
    	break;
    case KRB5_LIBOS_PWDINTR: /* don't print anything if it was just C-c:ed */
    	exit(1);
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KRB_AP_ERR_MODIFIED:
    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5_GET_IN_TKT_LOOP:
    	krb5_warnx(context, N_("Password incorrect", ""));
    	goto out;
    case KRB5KRB_AP_ERR_V4_REPLY:
    	krb5_warnx(context, N_("Looks like a Kerberos 4 reply", ""));
    	goto out;
    case KRB5KDC_ERR_KEY_EXPIRED:
    	krb5_warnx(context, N_("Password expired", ""));
    	goto out;
    default:
    	krb5_warn(context, ret, "krb5_get_init_creds");
    	goto out;
    }

    krb5_process_last_request(context, opt, ctx);

    ret = krb5_init_creds_get_creds(context, ctx, &cred);
    if (ret) {
    	krb5_warn(context, ret, "krb5_init_creds_get_creds");
    	goto out;
    }

    if (ticket_life != 0) {
		if (labs(cred.times.endtime - cred.times.starttime - ticket_life) > 30) {
			char life[64];
			unparse_time_approx(cred.times.endtime - cred.times.starttime,
					life, sizeof(life));
			krb5_warnx(context, N_("NOTICE: ticket lifetime is %s", ""), life);
		}
    }
    if (opts->renew_life) {
		if (labs(cred.times.renew_till - cred.times.starttime - renew) > 30) {
			char life[64];
			unparse_time_approx(cred.times.renew_till - cred.times.starttime,
					life, sizeof(life));
			krb5_warnx(context,
				   N_("NOTICE: ticket renewable lifetime is %s", ""),
				   life);
		}
    }
    krb5_free_cred_contents(context, &cred);

    ret = krb5_cc_new_unique(context, krb5_cc_get_type(context, ccache),
			     NULL, &tempccache);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_new_unique");
		goto out;
    }

    ret = krb5_init_creds_store(context, ctx, tempccache);
    if (ret) {
		krb5_warn(context, ret, "krb5_init_creds_store");
		goto out;
    }

    krb5_init_creds_free(context, ctx);
    ctx = NULL;

    ret = krb5_cc_move(context, tempccache, ccache);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_move");
		goto out;
    }
    tempccache = NULL;

    if (opts->switch_cache_flags)
    	krb5_cc_switch(context, ccache);

    if (opts->ok_as_delegate_flag || opts->windows_flag || opts->use_referrals_flag) {
		unsigned char d = 0;
		krb5_data data;

		if (opts->ok_as_delegate_flag || opts->windows_flag)
			d |= 1;
		if (opts->use_referrals_flag || opts->windows_flag)
			d |= 2;

		data.length = 1;
		data.data = &d;

		krb5_cc_set_config(context, ccache, NULL, "realm-config", &data);
    }

out:
    krb5_get_init_creds_opt_free(context, opt);
    if (ctx)
    	krb5_init_creds_free(context, ctx);
    if (tempccache)
    	krb5_cc_close(context, tempccache);

    if (enctype)
    	free(enctype);

    return ret;
}

static time_t
ticket_lifetime(krb5_context context, krb5_ccache cache, krb5_principal client,
		const char *server, time_t *renew)
{
    krb5_creds in_cred, *cred;
    krb5_error_code ret;
    time_t timeout;
    time_t curtime;

    memset(&in_cred, 0, sizeof(in_cred));

    if (renew != NULL)
        *renew = 0;

    ret = krb5_cc_get_principal(context, cache, &in_cred.client);
    if (ret) {
		krb5_warn(context, ret, "krb5_cc_get_principal");
		return 0;
    }
    ret = get_server(context, in_cred.client, server, &in_cred.server);
    if (ret) {
		krb5_free_principal(context, in_cred.client);
		krb5_warn(context, ret, "get_server");
		return 0;
    }

    ret = krb5_get_credentials(context, KRB5_GC_CACHED,
			       cache, &in_cred, &cred);
    krb5_free_principal(context, in_cred.client);
    krb5_free_principal(context, in_cred.server);
    if (ret) {
		krb5_warn(context, ret, "krb5_get_credentials");
		return 0;
    }
    curtime = time(NULL);
    timeout = cred->times.endtime - curtime;
    if (timeout < 0)
    	timeout = 0;
    if (renew) {
    	*renew = cred->times.renew_till - curtime;
    	if (*renew < 0)
    		*renew = 0;
    }
    krb5_free_creds(context, cred);
    return timeout;
}

static time_t expire;

static char siginfo_msg[1024] = "No credentials\n";

static void
update_siginfo_msg(time_t exp, const char *srv)
{
    /* Note that exp is relative time */
    memset(siginfo_msg, 0, sizeof(siginfo_msg));
    memcpy(&siginfo_msg, "Updating...\n", sizeof("Updating...\n"));
    if (exp) {
	if (srv == NULL) {
	    snprintf(siginfo_msg, sizeof(siginfo_msg),
		     N_("kinit: TGT expires in %llu seconds\n", ""),
		     (unsigned long long)expire);
	} else {
	    snprintf(siginfo_msg, sizeof(siginfo_msg),
		     N_("kinit: Ticket for %s expired\n", ""), srv);
	}
	return;
    }

    /* Expired creds */
    if (srv == NULL) {
    	snprintf(siginfo_msg, sizeof(siginfo_msg),
    			N_("kinit: TGT expired\n", ""));
    } else {
    	snprintf(siginfo_msg, sizeof(siginfo_msg),
    			N_("kinit: Ticket for %s expired\n", ""), srv);
    }
}

#ifdef HAVE_SIGACTION
static void
handle_siginfo(int sig)
{
    struct iovec iov[2];

    iov[0].iov_base = rk_UNCONST(siginfo_msg);
    iov[0].iov_len = strlen(siginfo_msg);
    iov[1].iov_base = "\n";
    iov[1].iov_len = 1;

    writev(STDERR_FILENO, iov, sizeof(iov)/sizeof(iov[0]));
}
#endif

struct renew_ctx {
    krb5_context context;
    krb5_ccache  ccache;
    krb5_principal principal;
    krb5_deltat ticket_life;
    krb5_deltat timeout;
};

static time_t
renew_func(void *ptr, k_opts * opts)
{
    krb5_error_code ret;
    struct renew_ctx *ctx = ptr;
    time_t renew_expire;
    static time_t exp_delay = 1;

    /*
     * NOTE: We count on the ccache implementation to notice changes to the
     * actual ccache filesystem/whatever objects.  There should be no ccache
     * types for which this is not the case, but it might not hurt to
     * re-krb5_cc_resolve() after each successful renew_validate()/
     * get_new_tickets() call.
     */

    expire = ticket_lifetime(ctx->context, ctx->ccache, ctx->principal,
    		opts->server_str, &renew_expire);

    /*
     * When a keytab is available to obtain new tickets, if we are within
     * half of the original ticket lifetime of the renew limit, get a new
     * TGT instead of renewing the existing TGT.  Note, ctx->ticket_life
     * is zero by default (without a '-l' option) and cannot be used to
     * set the time scale on which we decide whether we're "close to the
     * renew limit".
     */
    if (opts->use_keytab || opts->keytab_str)
    	expire += ctx->timeout;
    if (renew_expire > expire) {
    	ret = renew_validate(ctx->context, opts, 1, opts->validate_flag, ctx->ccache,
    			opts->server_str, ctx->ticket_life);
    } else {
    	ret = get_new_tickets(ctx->context, ctx->principal, ctx->ccache,
    			ctx->ticket_life, opts, 0);
    }
    expire = ticket_lifetime(ctx->context, ctx->ccache, ctx->principal,
    		opts->server_str, &renew_expire);

#ifndef NO_AFS
    if (ret == 0 && opts->server_str == NULL && opts->do_afslog && k_hasafs())
    	krb5_afslog(ctx->context, ctx->ccache, NULL, NULL);
#endif

    update_siginfo_msg(expire, opts->server_str);

    /*
     * If our tickets have expired and we been able to either renew them
     * or obtain new tickets, then we still call this function but we use
     * an exponential backoff.  This should take care of the case where
     * we are using stored credentials but the KDC has been unavailable
     * for some reason...
     */

    if (expire < 1) {
		/*
		 * We can't ask to keep spamming stderr but not syslog, so we warn
		 * only once.
		 */
		if (exp_delay == 1) {
			krb5_warnx(ctx->context, N_("NOTICE: Could not renew/refresh "
						"tickets", ""));
		}

		if (exp_delay < 7200)
			exp_delay += exp_delay / 2 + 1;
		return exp_delay;
    }
    exp_delay = 1;

    return expire / 2 + 1;
}

static void
set_princ_realm(krb5_context context,
		krb5_principal principal,
		const char *realm)
{
    krb5_error_code ret;

    if ((ret = krb5_principal_set_realm(context, principal, realm)) != 0)
    	krb5_err(context, 1, ret, "krb5_principal_set_realm");
}

static void
parse_name_realm(krb5_context context,
		 const char *name,
		 int flags,
		 const char *realm,
		 krb5_principal *princ)
{
    krb5_error_code ret;

    if (realm)
    	flags |= KRB5_PRINCIPAL_PARSE_NO_DEF_REALM;
    if ((ret = krb5_parse_name_flags(context, name, flags, princ)) != 0)
    	krb5_err(context, 1, ret, "krb5_parse_name_flags");
    if (realm && krb5_principal_get_realm(context, *princ) == NULL)
    	set_princ_realm(context, *princ, realm);
}

static void
get_default_principal(krb5_context context, krb5_principal *princ)
{
    krb5_error_code ret;

    if ((ret = krb5_get_default_principal(context, princ)) != 0)
    	krb5_err(context, 1, ret, "krb5_get_default_principal");
}

static char *
get_user_realm(krb5_context context)
{
    krb5_error_code ret;
    char *user_realm = NULL;

    /*
     * If memory allocation fails, we don't try to use the wrong realm,
     * that will trigger misleading error messages complicate support.
     */
    krb5_appdefault_string(context, "kinit", NULL, "user_realm", "",
			   &user_realm);
    if (user_realm == NULL) {
		ret = krb5_enomem(context);
		krb5_err(context, 1, ret, "krb5_appdefault_string");
    }

    if (*user_realm == 0) {
		free(user_realm);
		user_realm = NULL;
    }

    return user_realm;
}

static void
get_princ(krb5_context context, krb5_principal *principal, k_opts * opts, const char *name)
{
    krb5_error_code ret;
    krb5_principal tmp;
    int parseflags = 0;
    char *user_realm;

    if (name == NULL) {
		krb5_ccache ccache;

		/* If credential cache provides a client principal, use that. */
		if (krb5_cc_default(context, &ccache) == 0) {
			ret = krb5_cc_get_principal(context, ccache, principal);
			krb5_cc_close(context, ccache);
			if (ret == 0)
				return;
		}
    }

    user_realm = get_user_realm(context);

    if (name) {
		if (opts->canonicalize_flag || opts->enterprise_flag)
			parseflags |= KRB5_PRINCIPAL_PARSE_ENTERPRISE;

		parse_name_realm(context, name, parseflags, user_realm, &tmp);

		if (user_realm && krb5_principal_get_num_comp(context, tmp) > 1) {
			/* Principal is instance qualified, reparse with default realm. */
			krb5_free_principal(context, tmp);
			parse_name_realm(context, name, parseflags, NULL, principal);
		} else {
			*principal = tmp;
		}
    } else {
		get_default_principal(context, principal);
		if (user_realm)
			set_princ_realm(context, *principal, user_realm);
    }

    if (user_realm)
    	free(user_realm);
}

static krb5_error_code
get_switched_ccache(krb5_context context,
		    const char * type,
		    krb5_principal principal,
		    krb5_ccache *ccache)
{
    krb5_error_code ret;
    ret = krb5_cc_new_unique(context, type, NULL, ccache);
    return ret;
}

int k5_begin(k_opts * opts, struct k5_data* k5, rdpSettings * settings)
{
	krb5_error_code code = 0;
	int success = 0;
	int id_init = 0;
	int i = 0;
	int anchors_init = 1;
	krb5_ccache defcache = NULL;
	krb5_principal defcache_princ = NULL, princ = NULL;
	const char * deftype = NULL;
	char * defrealm=NULL, *name=NULL;
	char * pkinit_anchors = NULL;
	char * pkinit_certificate = NULL;
	char ** domain = &settings->Domain;

	/* set pkinit client certificate */
	if( settings->PkinitCertificate != NULL )
		pkinit_certificate = settings->PkinitCertificate;
	else{
		WLog_ERR(TAG, "%s : /pkinit-cert missing. Abort...", progname);
		return success;
	}

	/* set opts */
	opts->lifetime = settings->LifeTime;
	opts->rlife = settings->RenewableLifeTime;
	opts->forwardable_flag = 1;
	opts->canonicalize_flag = 1; /* Canonicalized UPN is required for credentials delegation (CredSSP) */

	opts->pk_enterprise_flag = 0; /* use principal name from settings */

	int flags = opts->enterprise_flag ? KRB5_PRINCIPAL_PARSE_ENTERPRISE : 0;

	opts->pk_user_id = (char*) settings->IdCertificate;

	/* set k5 string principal name */
	k5->name = opts->principal_name;

	/* set pkinit identities */
	/*id_init = add_preauth_opt(opts, pkinit_identity);
	if( id_init != 0 ){
		WLog_ERR(TAG, "%s : Error while setting pkinit identities", progname);
		goto cleanup;
	}*/


	/* set pkinit anchors */
	if( settings->PkinitAnchors != NULL )
		pkinit_anchors = settings->PkinitAnchors;
	else
		WLog_WARN(TAG, "%s : /pkinit-anchors missing. Retrieve anchors via krb5.conf", progname);


	/* set pkinit anchors */
	/*if(list_pkinit_anchors == NULL || (list_pkinit_anchors != NULL && (strlen(list_pkinit_anchors)==0)) ){
		WLog_WARN(TAG, "%s : /pkinit-anchors missing. Retrieve anchors via krb5.conf", progname);
	}
	else {
		opts->pkinit_anchors = parse_pkinit_anchors(list_pkinit_anchors);

		if(opts->pkinit_anchors == NULL){
			WLog_ERR(TAG, "%s : Fail to get pkinit anchors", progname);
			goto cleanup;
		}

		while(opts->pkinit_anchors && opts->pkinit_anchors[i]->anchor)
		{
			anchors_init = add_preauth_opt( opts, opts->pkinit_anchors[i]->anchor );
			if( anchors_init != 0 ){
				WLog_ERR(TAG, "%s : Error while setting pkinit anchors", progname);
				goto cleanup;
			}
			i++;
		}
	}*/

	/* get back domain in settings if not specified in command line */
	if(*domain == NULL){
		char * find_domain = strrchr(k5->name, '@');
		if(find_domain != NULL){
			*find_domain++ = '\0';
			*domain = calloc( strlen(find_domain) + 1, sizeof(char) );
			if(!(*domain)){
				WLog_ERR(TAG, "Error allocation domain");
				goto cleanup;
			}
			strncpy(*domain, find_domain, strlen(find_domain) + 1);
		}
		else{
			WLog_ERR(TAG, "Error getting back domain");
			goto cleanup;
		}
	}
	else{
		WLog_DBG(TAG, "Domain already specified in command line");
	}

	success = 1;

	return success;

cleanup:
	if(opts->pkinit_anchors != NULL){
		for( i=PKINIT_ANCHORS_MAX; i>0 ; i-- ){
			free(opts->pkinit_anchors[i-1]->anchor);
			opts->pkinit_anchors[i-1]->anchor = NULL;
			free(opts->pkinit_anchors[i-1]);
			opts->pkinit_anchors[i-1] = NULL;
		}
	}
	free(opts->pkinit_anchors);
	opts->pkinit_anchors = NULL;
	return success;
}

int k5_kinit(k_opts * opts, struct k5_data* k5, rdpSettings * rdpSettings)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache  ccache;
    krb5_principal principal = NULL;
    int optidx = 0;
    krb5_deltat ticket_life = 0;
#ifdef HAVE_SIGACTION
    struct sigaction sa;
#endif

//    setprogname(argv[0]);

#if defined(HEIMDAL_LOCALEDIR)
    setlocale(LC_ALL, "");
    bindtextdomain("heimdal_kuser", HEIMDAL_LOCALEDIR);
    textdomain("heimdal_kuser");
#endif

    ret = krb5_init_context(&context);
    if (ret == KRB5_CONFIG_BADFORMAT)
    	errx(1, "krb5_init_context failed to parse configuration file");
    else if (ret)
    	errx(1, "krb5_init_context failed: %d", ret);

//    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
//	usage(1);

/*    if (opts->help_flag)
	usage(0);

    if (opts->version_flag) {
	print_version(NULL);
	exit(0);
    }*/

//    argc -= optidx;
//    argv += optidx;

    if (opts->pk_enterprise_flag) {
	ret = krb5_pk_enterprise_cert(context, opts->pk_user_id,
				      opts->domain, &principal,
				      &(opts->ent_user_id) );
	if (ret)
	    krb5_err(context, 1, ret, "krb5_pk_enterprise_certs");

	opts->pk_user_id = NULL;

    } else if (opts->anonymous_flag) {

	ret = krb5_make_principal(context, &principal, opts->domain,
				  KRB5_WELLKNOWN_NAME, KRB5_ANON_NAME,
				  NULL);
	if (ret)
	    krb5_err(context, 1, ret, "krb5_make_principal");
	krb5_principal_set_type(context, principal, KRB5_NT_WELLKNOWN);

    } else {
    	get_princ(context, &principal, opts, k5->name);
    }

    if (opts->fcache_version)
    	krb5_set_fcache_version(context, opts->fcache_version);

    if (opts->renewable_flag == -1)
	/* this seems somewhat pointless, but whatever */
    	krb5_appdefault_boolean(context, "kinit",
				krb5_principal_get_realm(context, principal),
				"renewable", FALSE, &(opts->renewable_flag));
    if (opts->do_afslog == -1)
    	krb5_appdefault_boolean(context, "kinit",
				krb5_principal_get_realm(context, principal),
				"afslog", TRUE, &(opts->do_afslog));

    if (opts->cred_cache)
    	ret = krb5_cc_resolve(context, opts->cred_cache, &ccache);
    else {
//	if (argc > 1) {
	    char s[1024];
	    ret = krb5_cc_new_unique(context, NULL, NULL, &ccache);
	    if (ret)
		krb5_err(context, 1, ret, "creating cred cache");
	    snprintf(s, sizeof(s), "%s:%s",
		     krb5_cc_get_type(context, ccache),
		     krb5_cc_get_name(context, ccache));
	    setenv("KRB5CCNAME", s, 1);
//    }
#ifdef argsup1
    else {
	    ret = krb5_cc_cache_match(context, principal, &ccache);
	    if (ret) {
			const char *type;
			ret = krb5_cc_default(context, &ccache);
			if (ret)
				krb5_err(context, 1, ret,
					 N_("resolving credentials cache", ""));

			/*
			 * Check if the type support switching, and we do,
			 * then do that instead over overwriting the current
			 * default credential
			 */
			type = krb5_cc_get_type(context, ccache);
			if (krb5_cc_support_switch(context, type)) {
				krb5_cc_close(context, ccache);
				ret = get_switched_ccache(context, type, principal,
							  &ccache);
			}
	    }
	}
#endif
    }
    if (ret)
	krb5_err(context, 1, ret, N_("resolving credentials cache", ""));

#ifndef NO_AFS
    if (/*argc > 1 &&*/ k_hasafs())
	k_setpag();
#endif

    if (opts->lifetime_s) {
	int tmp = parse_time(opts->lifetime_s, "s");
	if (tmp < 0)
	    errx(1, N_("unparsable time: %s", ""), opts->lifetime_s);

	ticket_life = tmp;
    }

    if (opts->addrs_flag == 0 && opts->extra_addresses.num_strings > 0)
    	krb5_errx(context, 1,
		  N_("specifying both extra addresses and "
		     "no addresses makes no sense", ""));
    {
		int i;
		krb5_addresses addresses;
		memset(&addresses, 0, sizeof(addresses));
		for(i = 0; i < opts->extra_addresses.num_strings; i++) {
			ret = krb5_parse_address(context, opts->extra_addresses.strings[i],
						 &addresses);
			if (ret == 0) {
				krb5_add_extra_addresses(context, &addresses);
				krb5_free_addresses(context, &addresses);
			}
		}
		free_getarg_strings(&(opts->extra_addresses));
    }

    if (opts->renew_flag || opts->validate_flag) {
	ret = renew_validate(context, opts, opts->renew_flag, opts->validate_flag,
			     ccache, opts->server_str, ticket_life);

#ifndef NO_AFS
	if (ret == 0 && opts->server_str == NULL && opts->do_afslog && k_hasafs())
	    krb5_afslog(context, ccache, NULL, NULL);
#endif

	exit(ret != 0);
    }

    ret = get_new_tickets(context, principal, ccache, ticket_life, opts, 1);
    if (ret)
    	exit(1);

#ifndef NO_AFS
    if (ret == 0 && opts->server_str == NULL && opts->do_afslog && k_hasafs())
    	krb5_afslog(context, ccache, NULL, NULL);
#endif

    /*if (argc > 1) {*/
	struct renew_ctx ctx;
	time_t timeout;

	timeout = ticket_lifetime(context, ccache, principal,
			opts->server_str, NULL) / 2;

	ctx.context = context;
	ctx.ccache = ccache;
	ctx.principal = principal;
	ctx.ticket_life = ticket_life;
	ctx.timeout = timeout;

#ifdef HAVE_SIGACTION
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handle_siginfo;

	sigaction(SIGINFO, &sa, NULL);
#endif

//	ret = simple_execvp_timed(argv[1], argv+1,
//				  renew_func, &ctx, timeout);
#define EX_NOEXEC	126
#define EX_NOTFOUND	127
//	if (ret == EX_NOEXEC)
//	    krb5_warnx(context, N_("permission denied: %s", ""), argv[1]);
//	else if (ret == EX_NOTFOUND)
//	    krb5_warnx(context, N_("command not found: %s", ""), argv[1]);

	krb5_cc_destroy(context, ccache);
#ifndef NO_AFS
	if (k_hasafs())
	    k_unlog();
#endif
    /*} else {
	krb5_cc_close(context, ccache);
	ret = 0;
    }*/
    krb5_free_principal(context, principal);
    if (opts->kt)
	krb5_kt_close(context, opts->kt);
    krb5_free_context(context);
    return ret;
}

static krb5_context errctx;
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

BOOL init_cred_cache(rdpSettings * settings)
{
	k_opts opts;
	struct k5_data k5;
	int authed_k5 = 0;

	memset(&opts, 0, sizeof(opts));
	memset(&k5, 0, sizeof(k5));

//	set_com_err_hook (extended_com_err_fn);

	/* make KRB5 PKINIT verbose */
	if( settings->Krb5Trace )
		opts.verbose = 1;

	opts.principal_name = calloc(strlen(settings->UserPrincipalName)+1, sizeof(char) );
	if(opts.principal_name == NULL)
		return FALSE;
	strncpy(opts.principal_name, settings->UserPrincipalName, strlen(settings->UserPrincipalName) );
	opts.principal_name[strlen(settings->UserPrincipalName)] = '\0';

	/* if /d:domain is specified in command line, set it as Kerberos default realm */
	if( settings->Domain ){
		opts.principal_name = realloc( opts.principal_name, strlen(settings->UserPrincipalName) + 1 + strlen(settings->Domain) + 1 );
		if(opts.principal_name == NULL){
			free(opts.principal_name);
			return FALSE;
		}
		strncat(opts.principal_name, "@", 1);
		strncat(opts.principal_name, settings->Domain, strlen(settings->Domain) );
		opts.principal_name[strlen(settings->UserPrincipalName) + 1 + strlen(settings->Domain)] = '\0';
	}

	char * pstr = NULL;
	pstr = strchr(settings->UserPrincipalName, '@');
	if(pstr != NULL){
		opts.enterprise_flag = KRB5_PRINCIPAL_PARSE_ENTERPRISE;
	}

	/* Start time is the time when ticket (TGT) issued by the KDC become valid.
	 * It needs to be different from 0 to request a postdated ticket.
	 * And thus, enable validation of credentials by the KDC, that can only validate postdated ticket */
	opts.starttime = settings->StartTime;

	if ( k5_begin(&opts, &k5, settings) )
		authed_k5 = k5_kinit(&opts, &k5, settings);

	if( authed_k5 && opts.outdata->data ){
		settings->CanonicalizedUserHint = _strdup(opts.outdata->data);
		if(settings->CanonicalizedUserHint == NULL){
			WLog_ERR(TAG, "Error _strdup outdata into canonicalized user hint");
			authed_k5 = 0;
		}
		krb5_free_data(k5.ctx, opts.outdata);
	}

	if (authed_k5)
		WLog_INFO(TAG, "Authenticated to Kerberos v5 via smartcard");

	/* free */
	k5_end(&k5);

	if (!authed_k5){
		WLog_ERR(TAG, "Credentials cache initialization failed !");
		return FALSE;
	}

	return TRUE;
}

/** pkinit_acquire_krb5_TGT is used to acquire credentials via Kerberos.
 *  This function is actually called in get_TGT_kerberos().
 *  @param krb_settings - pointer to the kerberos_settings structure
 *  @return TRUE if valid TGT acquired, FALSE otherwise
 */
BOOL pkinit_acquire_krb5_TGT(rdpSettings * settings)
{
	WLog_DBG(TAG, "PKINIT starting...");

	if( !set_pkinit_identity(settings) )
	{
		WLog_ERR(TAG, "%s %d : Error while setting pkinit_identity", __FUNCTION__,  __LINE__);
		return FALSE;
	}

	BOOL ret_pkinit = init_cred_cache(settings);

	if(ret_pkinit == FALSE)
		return FALSE;

	return TRUE;
}

/** get_TGT_kerberos is used to get TGT from KDC.
 *  This function is actually called in nla_client_init().
 *  @param settings - pointer to rdpSettings structure that contains the settings
 *  @return TRUE if the Kerberos negotiation was successful.
 */
BOOL get_TGT_kerberos(rdpSettings * settings)
{
	if( pkinit_acquire_krb5_TGT(settings) == FALSE )
		return FALSE;
	else
		WLog_DBG(TAG, "PKINIT : successfully acquired TGT");

	return TRUE;
}


#endif // COUCOU
