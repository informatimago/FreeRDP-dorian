#include <stdio.h>
#include <string.h>

#include "../pkcs11errors.h"

#define FAILURE(format, ...)						\
	do								\
	{								\
		printf("%s:%d: in %s() FAILURE ",			\
			__FILE__, __LINE__, __FUNCTION__);		\
		printf(format, ## __VA_ARGS__);				\
	}while (0)


static int check(const char * label, CK_RV rv)
{
	if (0 == strcmp(label, pkcs11_return_value_label(rv)))
	{
		return 0;
	}

	FAILURE("Mismatch for %s", label);
	return 1;
}



int Test_pkcs11errors(int argc, char* argv[])
{
	int failure = 0;

#define CHECK(rv) (failure |= check(#rv, rv))
	
	CK_RV rv;
	for (rv = 0;rv < 520;rv ++ )
	{
		printf("(CK_RV)%4d = %-40s\n", rv, pkcs11_return_value_label(rv));
	}

	CHECK(CKR_OK);
	CHECK(CKR_FUNCTION_REJECTED);
	CHECK(CKR_FUNCTION_NOT_SUPPORTED);
	failure |= check("Unknown CR_RV value: 4 (0x4)", 4);
	failure |= check("Unknown CR_RV value: 510 (0x1fe)", 510);
	CHECK(CKR_MUTEX_BAD);
	return failure;
}

