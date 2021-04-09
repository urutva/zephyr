/*
 * Copyright (c) 2019,2020 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>
#include <data/json.h>

#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"

#include "tfm_ns_interface.h"
#include "psa_attestation.h"
#include "psa_crypto.h"
#include "util_app_cfg.h"
#include "util_app_log.h"
#include "util_sformat.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/* Create an instance of the system config struct for the application. */
static struct cfg_data cfg;

struct csr_json_struct {
    const char *CSR;
};

static const struct json_obj_descr csr_json_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct csr_json_struct, CSR, JSON_TOK_STRING)
};

int generate_csr_using_mbedtls()
{
    int ret = 1;
    mbedtls_pk_context key;
    unsigned char output_buf[1024];
    unsigned char base64_encoded_buf[1024];
    size_t use_len;

    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "csr example app";

    const mbedtls_ecp_curve_info *curve_info;

    struct csr_json_struct csr_json = {
        .CSR = base64_encoded_buf
    };

    /*
    * Set to sane values
    */
    mbedtls_x509write_csr_init( &req );
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( output_buf, 0, sizeof( output_buf ) );
    memset( base64_encoded_buf, 0, sizeof( base64_encoded_buf ) );

    mbedtls_x509write_csr_set_md_alg( &req, MBEDTLS_MD_SHA256 );

    /*
    * 0. Seed the PRNG
    */
    printf( "  . Seeding the random number generator...\n" );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *) pers,
                                        strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  !  mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
    * 1.0. Check the subject name for validity
    */
    printf( "  . Checking subject name...\n" );

    if( ( ret = mbedtls_x509write_csr_set_subject_name( &req, "O=Linaro,CN=Device Certificate" ) ) != 0 )
    {
        printf( " failed\n  !  mbedtls_x509write_csr_set_subject_name returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
    * 1.1. Generate the key
    */
    printf( " . Generating the private key ...\n" );

    curve_info = mbedtls_ecp_curve_info_from_name("secp256r1");

    if( ( ret = mbedtls_pk_setup( &key,
        mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) ) != 0 )
    {
        printf( " failed\n  !  mbedtls_pk_setup returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    ret = mbedtls_ecp_gen_key( curve_info->grp_id,
                                mbedtls_pk_ec( key ),
                                mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        printf( " failed\n  !  mbedtls_ecp_gen_key returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
    * 1.2. Load the key
    */
    printf( " . Loading the private key ...\n" );

    mbedtls_x509write_csr_set_key( &req, &key );

    printf( " ok\n" );

    /*
    * 1.3. Writing the request
    */
    printf( "  . Writing the CSR ...\n" );

    ret = mbedtls_x509write_csr_der( &req, output_buf, sizeof(output_buf), mbedtls_ctr_drbg_random, &ctr_drbg );

    if( ret < 0 )
    {
        printf( " failed\n  !  mbedtls_x509write_csr_pem returned -0x%04x\n", (unsigned int) -ret );
        goto exit;
    }

    printf( " ok\n" );

    printf( "  . base64 encoding CSR in der format...\n" );

    mbedtls_base64_encode( base64_encoded_buf, sizeof(base64_encoded_buf), &use_len,
                            (output_buf + sizeof(output_buf) - ret),
                            ret );

    printf( " ok\n" );
    base64_encoded_buf[use_len] = '\0';

    /*
    * 1.3. Encoding CSR as JSON
    */
    printf( "  . Encoding CSR as json ...\n" );

    memset( output_buf, 0, sizeof( output_buf ) );

    ret = json_obj_encode_buf(csr_json_descr, ARRAY_SIZE(csr_json_descr),
                                &csr_json, output_buf, sizeof(output_buf));

    if( ret != 0 )
    {
        printf( " failed\n  !  json_obj_encode_buf returned 0x%04x\n", ret );
        goto exit;
    }

    printf( " ok\n" );
    printf("%s\n", output_buf);

exit:
    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    if (ret < 0) {
        return ret;
    } else {
        return 0;
    }
}

void main(void)
{
    /* Initialize the TFM NS interface */
    tfm_ns_interface_init();

    /* Initialise the logger subsys and dump the current buffer. */
    log_init();

    /* Load app config struct from secure storage (create if missing). */
    if (cfg_load_data(&cfg)) {
        LOG_ERR("Error loading/generating app config data in SS.");
    }

    /* Get the entity attestation token (requires ~1kB stack memory!). */
    att_test();

    /* Crypto tests */
    crp_test();

    /* Generate Certificate Signing Request using Mbed TLS */
    generate_csr_using_mbedtls();

    /* Dump any queued log messages, and wait for system events. */
    al_dump_log();
}
