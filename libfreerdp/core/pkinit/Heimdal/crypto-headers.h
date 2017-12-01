#ifndef __crypto_header__
#define __crypto_header__

//#ifndef PACKAGE_NAME
//#error "need config.h"
//#endif

#ifdef KRB5
#include <krb5-types.h>
#endif

#include <heimdal/hcrypto/evp.h>
#include <heimdal/hcrypto/des.h>
#include <heimdal/hcrypto/md4.h>
#include <heimdal/hcrypto/md5.h>
#include <heimdal/hcrypto/sha.h>
#include <heimdal/hcrypto/rc4.h>
#include <heimdal/hcrypto/rc2.h>
#include <heimdal/hcrypto/ui.h>
#include <heimdal/hcrypto/rand.h>
#include <heimdal/hcrypto/engine.h>
#include <heimdal/hcrypto/pkcs12.h>
#include <heimdal/hcrypto/hmac.h>

#endif /* __crypto_header__ */
