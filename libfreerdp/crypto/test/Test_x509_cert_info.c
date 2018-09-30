#include <freerdp/crypto/crypto.h>

#define countof(a)   (sizeof(a)/sizeof(a[0]))

#define FAILURE(format, ...)						\
	do								\
	{								\
		printf("%s:%d: in %s() FAILURE ",			\
			__FILE__, __LINE__, __FUNCTION__);		\
		printf(format, ## __VA_ARGS__);				\
	}while (0)


typedef char *  (*get_field_pr)(X509 *);
typedef struct {
        enum
        {
                DISABLED, ENABLED,
        } status;
        int type;
        const char * field_description;
        get_field_pr get_field;
        const char * expected_results[CERT_INFO_SIZE];
} certificate_test_t;

char *  crypto_cert_subject_common_name_wo_length(X509 * xcert)
{
        int length;
        return crypto_cert_subject_common_name(xcert, & length);
}

const char * certificate_path = "Test_x509_cert_info.pem";
const certificate_test_t certificate_tests[]
= {

        {ENABLED, CERT_CN          , "Certificate Common Name",
         crypto_cert_subject_common_name_wo_length,
         {"TESTJEAN TESTMARTIN 9999999", 0}},

        {ENABLED, CERT_SUBJECT     , "Certificate subject",
         crypto_cert_subject,
         {"CN = TESTJEAN TESTMARTIN 9999999, C = FR, O = MINISTERE DES TESTS, OU = 0002 110014016, OU = PERSONNES, UID = 9999999, GN = TESTJEAN, SN = TESTMARTIN", 0}},

	{DISABLED, CERT_KPN         , "Kerberos principal name",
         0,
         {"testjean.testmartin@kpn.test.example.com", 0}},

        {ENABLED, CERT_EMAIL       , "Certificate e-mail",
         0,
         {"testjean.testmartin@test.example.com", 0}},

        {ENABLED, CERT_UPN         , "Microsoft's Universal Principal Name",
         0,
         {"testjean.testmartin.9999999@upn.test.example.com", 0}},

        {ENABLED, CERT_ISSUER      , "Certificate issuer",
         crypto_cert_issuer,
         {"CN = ADMINISTRATION CENTRALE DES TESTS, C = FR, O = MINISTERE DES TESTS, OU = 0002 110014016", 0}},

        {DISABLED, CERT_KEY_ALG     , "Certificate key algorithm",
         0,
         {"rsaEncryption", 0}}
};


int TestCertificateFile(const char *certificate_path, const certificate_test_t * certificate_tests, int count)
{
        X509 *  certificate;
        FILE *  certificate_file = fopen(certificate_path, "r");
        int success = 0;
        int i;

        if (!certificate_file)
        {
                FAILURE("cannot open certificate file '%s'\n", certificate_path);
                return -1;
        }

        certificate = PEM_read_X509(certificate_file, 0, 0, 0);
        if (!certificate)
        {
                FAILURE("cannot read certificate file '%s'\n", certificate_path);
                success = -1;
                goto fail;
        }


        for (i = 0;i < count;i ++ )
        {
                int r;
                char * crypto_result;
                x509_cert_info_t* info;

                if (certificate_tests[i].status == DISABLED)
                {
                        continue;
                }

                info = x509_cert_info(certificate, certificate_tests[i].type);
                if (info)
                {
                        const char *  sep = "";
                        printf("%s: x509_cert_info %s -> ", __FUNCTION__,
                                certificate_tests[i].field_description);
                        for (r = 0;r < info->count;r ++ )
                        {
                                printf("%s%s", sep, info->entries[r]);
                                sep = ", ";
                        }
                        printf("\n");
                }
                else
                {
                        FAILURE("[%d] cannot get x509_cert_info: %s\n", i, certificate_tests[i].field_description);
                }

                crypto_result = (certificate_tests[i].get_field
                        ? certificate_tests[i].get_field(certificate)
                        : 0);

                if (crypto_result)
                {
                        printf("%s: crypto get     %s -> %s\n", __FUNCTION__,
                                certificate_tests[i].field_description,
                                crypto_result);
                }
                else
                {
                        FAILURE("[%d] cannot get crypto info: %s\n", i, certificate_tests[i].field_description);

                }


                // check crypto_result
                if (crypto_result)
                {
                        for (r = 0;certificate_tests[i].expected_results[r]; r ++ )
                        {
                                if (1 <= r)
                                {
                                        FAILURE("[%d] for crypto info %s, more expected results than actual: [%d] = '%s'\n",
						i,
                                                certificate_tests[i].field_description,
                                                r, certificate_tests[i].expected_results[r]);
                                        success = -1;
                                        continue;
                                }
                                if (0 != strcmp(certificate_tests[i].expected_results[r], crypto_result))
                                {
                                        FAILURE("[%d] for crypto info %s,  actual: [%d] -> '%s' expected '%s'\n",
						i,
                                                certificate_tests[i].field_description,
                                                r,
                                                crypto_result,
                                                certificate_tests[i].expected_results[r]);
                                        success = -1;
                                }
                        }
                }

                // check x509_cert_info result:
                if (!info)

                {
                        continue;
                }
                for (r = 0;certificate_tests[i].expected_results[r]; r ++ )
                {
                        if (info->count <= r)
                        {
                                FAILURE("for x509_cert_info %s, more expected results than actual: [%d] = '%s'\n",
                                        certificate_tests[i].field_description,
                                        r, certificate_tests[i].expected_results[r]);
                                success = -1;
                                continue;
                        }
                        if (0 != strcmp(certificate_tests[i].expected_results[r], info->entries[r]))
                        {
                                FAILURE("for x509_cert_info %s,  actual: [%d] -> '%s' expected '%s'\n",
                                        certificate_tests[i].field_description,
                                        r,
                                        info->entries[r],
                                        certificate_tests[i].expected_results[r]);
                                success = -1;
                        }
                }
                while(r < info->count)
                {
                        FAILURE("for x509_cert_info %s, more actual results than expected: [%d] = '%s'\n",
                                certificate_tests[i].field_description,
                                r,
                                info->entries[r]);
                        success = -1;
                        r ++ ;
                }

                // Compare results:
                if (crypto_result)
                {
                        switch (info->count)
                        {
                            case 0:
                                    FAILURE("for %s, crypto got result: '%s',  but x509_cert_info did not.\n",
                                            certificate_tests[i].field_description,
                                            crypto_result);
                                    success = -1;
                                    break;
                            default:
				    FAILURE("for %s, x509_cert_info got %lu results.\n",
                                            certificate_tests[i].field_description,
                                            info->count);
                                    success = -1;
                                    /* fall thru */
                            case 1:
                                    if (0 != strcmp(crypto_result, info->entries[0]))
                                    {
                                            FAILURE("for %s, crypto got result: '%s',  but x509_cert_info got '%s'.\n",
                                                    certificate_tests[i].field_description,
                                                    crypto_result,
                                                    info->entries[0]);
                                            success = -1;
                                    }
                                    break;
                        }
                }
                else
                {
                        if (info->count != 0)
                        {
                                FAILURE("for %s, x509_cert_info got %lu results starting with '%s',  but crypto got none.\n",
                                        certificate_tests[i].field_description,
                                        info->count, info->entries[0]);
                        }
                }

                x509_cert_info_free(info);
        }

fail:
        fclose(certificate_file);
        return success;
}


int Test_x509_cert_info(int argc, char* argv[])
{
        return TestCertificateFile(certificate_path, certificate_tests, countof(certificate_tests));
}

