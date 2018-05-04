#include <freerdp/crypto/crypto.h>


#define countof(a)   (sizeof(a)/sizeof(a[0]))

typedef char *  (*get_field_pr)(X509 *);
typedef struct {
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
= {{CERT_CN          , "Certificate Common Name",
    crypto_cert_subject_common_name_wo_length,
    // {"www.mycompany.com", 0}
    {"TESTJEAN TESTMARTIN 9999999", 0}},
   {CERT_SUBJECT     , "Certificate subject",
    crypto_cert_subject, 
    // {"C = US, ST = OR, L = Portland, O = MyCompany, OU = MyDivision, CN = www.mycompany.com", 0}
    {"C = FR, O = MINISTERE DES TESTS, OU = PERSONNES, UID = 9999999, GN = TESTJEAN, SN = TESTMARTIN, CN = TESTJEAN TESTMARTIN 9999999, msUPN = testjean.testmartin.9999999@mintest.fr, emailAddress = testjean.testmartin@test.gouv.fr", 0}},
   {CERT_KPN         , "Kerberos principal name",
    0, 
    {0}},
   {CERT_EMAIL       , "Certificate e-mail",
    0, 
    // {"test@example.com", 0}
    {"testjean.testmartin@test.gouv.fr", 0}},
   {CERT_UPN         , "Microsoft's Universal Principal Name",
    0, 
    // {0}
    {"testjean.testmartin.9999999@mintest.fr", 0}},
   {CERT_ISSUER      , "Certificate issuer",
    crypto_cert_issuer, 
    // {"C = US, ST = OR, L = Portland, O = MyCompany, OU = MyDivision, CN = www.mycompany.com", 0}
    {"C = FR, O = MINISTERE DES TESTS, OU = PERSONNES, OU = 9999999, UID = TESTJEAN, GN = TESTMARTIN, SN = TESTJEAN TESTMARTIN 9999999, CN = testjean.testmartin.9999999@mintest.frAB00testjean.testmartin@test.gouv.fr"}}, 
   {CERT_KEY_ALG     , "Certificate key algorithm",
    0, 
    {"rsaEncryption", 0}}};


int TestCertificateFile(const char *certificate_path, const certificate_test_t * certificate_tests, int count)
{
        X509 *  certificate;
        FILE *  certificate_file = fopen(certificate_path, "r");
        int success = 0;
        int i;
        
        if (!certificate_file)
        {
                printf("%s: failure: cannot open certificate file '%s'\n", __FUNCTION__, certificate_path);
                return -1;
        }

        certificate = PEM_read_X509(certificate_file, 0, 0, 0);
        if (!certificate)
        {
                printf("%s: failure: cannot read certificate file '%s'\n", __FUNCTION__, certificate_path);
                success = -1;
                goto fail;
        }


        for (i = 0;i < count;i ++ )
        {
                int r;
                x509_cert_info_t* info = x509_cert_info(certificate, certificate_tests[i].type);
                if (!info)
                {
                        printf("%s: failure: cannot get x509_cert_info: %s\n", __FUNCTION__,
                                certificate_tests[i].field_description);
                        continue;
                }

                if (certificate_tests[i].get_field)
                {
                        char * crypto_result = certificate_tests[i].get_field(certificate);
                        if (crypto_result)
                        {
                                switch (info->count)
                                {
                                    case 0:
                                            printf("%s: failure for %s, crypto got result: '%s',  but x509_cert_info did not.\n",
                                                    __FUNCTION__,
                                                    certificate_tests[i].field_description,
                                                    crypto_result);
                                            success = -1;
                                            break;
                                    default:
                                            printf("%s: failure for %s, x509_cert_info got %d results.\n",
                                                    __FUNCTION__,
                                                    certificate_tests[i].field_description,
                                                    info->count);
                                            success = -1;
                                            /* fall thru */ 
                                    case 1:
                                            if (0 != strcmp(crypto_result, info->entries[0]))
                                            {
                                                    printf("%s: failure for %s, crypto got result: '%s',  but x509_cert_info got '%s'.\n",
                                                            __FUNCTION__,
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
                                        printf("%s: for %s, x509_cert_info got %d results starting with '%s',  byt crypto got none.\n",
                                                __FUNCTION__,
                                                certificate_tests[i].field_description,
                                                info->count, info->entries[0]);
                                }
                        }
                }

                for (r = 0;certificate_tests[i].expected_results[r]; r ++ )
                {
                        if (info->count <= r)
                        {
                                printf("%s: failure for %s, more expected results than actual: [%d] = '%s'\n",
                                        __FUNCTION__,
                                        certificate_tests[i].field_description,
                                        r, certificate_tests[i].expected_results[r]);
                                success = -1;
                                continue;
                        }
                        if (0 != strcmp(certificate_tests[i].expected_results[r], info->entries[r]))
                        {
                                printf("%s: failure for %s,  actual: [%d] -> '%s' expected '%s'\n",
                                        __FUNCTION__,
                                        certificate_tests[i].field_description,
                                        r,
                                        info->entries[r],
                                        certificate_tests[i].expected_results[r]);
                                success = -1;
                        }
                }
                while(r < info->count)
                {
                        printf("%s: failure for %s, more actual results than expected: [%d] = '%s'\n",
                                __FUNCTION__,
                                certificate_tests[i].field_description,
                                r,
                                info->entries[r]);
                        success = -1;
                        r ++ ;
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

