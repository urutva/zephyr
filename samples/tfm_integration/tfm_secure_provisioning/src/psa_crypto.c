/*
 * Copyright (c) 2021 Linaro Limited
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
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"

#include "tfm_secure_provisioning_api.h"
#include "psa_crypto.h"
#include "util_app_log.h"
#include "util_sformat.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

/* Formatting details for displaying hex dumps. */
struct sf_hex_tbl_fmt crp_fmt = {
	.ascii = true,
	.addr_label = true,
	.addr = 0
};

struct csr_json_struct {
	const char *CSR;
};

static const struct json_obj_descr csr_json_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct csr_json_struct, CSR, JSON_TOK_STRING)
};

/**
 * @brief Extracts the public key from the specified persistent key id.
 *
 * @param key_id        The permament identifier for the generated key.
 * @param key           Pointer to the buffer where the public key data
 *                      will be written.
 * @param key_buf_size  Size of key buffer in bytes.
 * @param key_len       Number of bytes written into key by this function.
 */
static psa_status_t crp_get_pub_key(psa_key_id_t key_id,
				    uint8_t *key, size_t key_buf_size,
				    size_t *key_len)
{
	psa_status_t status;
	psa_key_handle_t key_handle;

	LOG_INF("Retrieving public key for key #%d", key_id);
	al_dump_log();

	/* Now try to re-open the persisted key based on the key ID. */
	status = al_psa_status(
		psa_open_key(key_id, &key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to open persistent key #%d", key_id);
		goto err;
	}

	/* Export the persistent key's public key part. */
	status = al_psa_status(
		psa_export_public_key(key_handle, key, key_buf_size, key_len),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to export public key.");
		goto err;
	}

	/* Display the binary key data for debug purposes. */
	sf_hex_tabulate_16(&crp_fmt, key, *key_len);

	/* Close the key to free up the volatile slot. */
	status = al_psa_status(
		psa_close_key(key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to close persistent key.");
		goto err;
	}

	return status;
err:
	al_dump_log();
	return status;
}

#if CONFIG_PSA_IMPORT_KEY
/**
 * @brief Stores a new persistent secp256r1 key (usage: ecdsa-with-SHA256)
 *        in ITS, associating it with the specified unique key identifier.
 *
 * This function will store a new persistent secp256r1 key in internal trusted
 * storage. Cryptographic operations can then be performed using the key
 * identifier (key_id) associated with this persistent key. Only the 32-byte
 * private key needs to be supplied, the public key can be derived using
 * the supplied private key value.
 *
 * @param key_id        The permament identifier for the generated key.
 * @param key_usage     The usage policy for the key.
 * @param key_data      Pointer to the 32-byte private key data.
 */
static psa_status_t crp_imp_key_secp256r1(psa_key_id_t key_id,
					  psa_key_usage_t key_usage,
					  uint8_t *key_data)
{
	psa_status_t status = PSA_SUCCESS;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_type_t key_type =
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
	psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	psa_key_handle_t key_handle;
	size_t key_len = 32;
	size_t data_len;
	uint8_t data_out[65] = { 0 }; /* ECDSA public key = 65 bytes. */
	int comp_result;

	LOG_INF("Persisting SECP256R1 key as #%d", (uint32_t)key_id);
	al_dump_log();

	/* Setup the key's attributes before the creation request. */
	psa_set_key_id(&key_attributes, key_id);
	psa_set_key_usage_flags(&key_attributes, key_usage);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_type(&key_attributes, key_type);

	/* Import the private key, creating the persistent key on success */
	status = al_psa_status(
		psa_import_key(&key_attributes, key_data, key_len, &key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to import key.");
		goto err;
	}

	/* Close the key to free up the volatile slot. */
	status = al_psa_status(
		psa_close_key(key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to close persistent key.");
		goto err;
	}

	/* Try to retrieve the public key. */
	status = crp_get_pub_key(key_id, data_out, sizeof(data_out), &data_len);

	/* Export the private key if usage includes PSA_KEY_USAGE_EXPORT. */
	if (key_usage & PSA_KEY_USAGE_EXPORT) {
		/* Re-open the persisted key based on the key ID. */
		status = al_psa_status(
			psa_open_key(key_id, &key_handle),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to open persistent key #%d", key_id);
			goto err;
		}

		/* Read the original (private) key data back. */
		status = al_psa_status(
			psa_export_key(key_handle, data_out,
				       sizeof(data_out), &data_len),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to export key.");
			goto err;
		}

		/* Check key len. */
		if (data_len != key_len) {
			LOG_ERR("Unexpected number of bytes in exported key.");
			goto err;
		}

		/* Verify that the exported private key matches input data. */
		comp_result = memcmp(data_out, key_data, key_len);
		if (comp_result != 0) {
			LOG_ERR("Imported/exported private key mismatch.");
			goto err;
		}

		/* Display the private key. */
		LOG_INF("Private key data:");
		al_dump_log();
		sf_hex_tabulate_16(&crp_fmt, data_out, data_len);

		/* Close the key to free up the volatile slot. */
		status = al_psa_status(
			psa_close_key(key_handle),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to close persistent key.");
			goto err;
		}
	}

	return status;
err:
	al_dump_log();
	return status;
}

#else /* !CONFIG_PSA_IMPORT_KEY */
/**
 * @brief Generates a new permanent, persistent prime256v1 (ecdsa-with-SHA256)
 *        key in ITS, associating it with the specified unique key identifier.
 *
 * This function will generate a new permament prime256v1 key in internal trusted
 * storage. Cryptographic operations can then be performed using the key
 * identifier (key_id) associated with this persistent key.
 *
 * @param key_id        The permament identifier for the generated key.
 * @param key_usage     The usage policy for the key.
 */
static psa_status_t crp_gen_key_secp256r1(psa_key_id_t key_id,
					  psa_key_usage_t key_usage)
{
	psa_status_t status = PSA_SUCCESS;
	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_type_t key_type =
		PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
	psa_algorithm_t alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
	psa_key_handle_t key_handle;
	size_t key_len = 32;
	size_t data_len;
	uint8_t data_out[65] = { 0 }; /* ECDSA public key = 65 bytes. */

	LOG_INF("Persisting SECP256R1 key as #%d", (uint32_t)key_id);
	al_dump_log();

	/* Setup the key's attributes before the creation request. */
	psa_set_key_id(&key_attributes, key_id);
	psa_set_key_usage_flags(&key_attributes, key_usage);
	psa_set_key_lifetime(&key_attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_algorithm(&key_attributes, alg);
	psa_set_key_type(&key_attributes, key_type);
	psa_set_key_bits(&key_attributes, 256);

	/* Generate the private key, creating the persistent key on success */
	status = al_psa_status(
		psa_generate_key(&key_attributes, &key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to generate key.");
		goto err;
	}

	/* Close the key to free up the volatile slot. */
	status = al_psa_status(
		psa_close_key(key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to close persistent key.");
		goto err;
	}

	/* Try to retrieve the public key. */
	status = crp_get_pub_key(key_id, data_out, sizeof(data_out), &data_len);

	/* Export the private key if usage includes PSA_KEY_USAGE_EXPORT. */
	if (key_usage & PSA_KEY_USAGE_EXPORT) {
		/* Re-open the persisted key based on the key ID. */
		status = al_psa_status(
			psa_open_key(key_id, &key_handle),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to open persistent key #%d", key_id);
			goto err;
		}

		/* Read the original (private) key data back. */
		status = al_psa_status(
			psa_export_key(key_handle, data_out,
				       sizeof(data_out), &data_len),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to export key.");
			goto err;
		}

		/* Check key len. */
		if (data_len != key_len) {
			LOG_ERR("Unexpected number of bytes in exported key.");
			goto err;
		}

		/* Display the private key. */
		LOG_INF("Private key data:");
		al_dump_log();

		sf_hex_tabulate_16(&crp_fmt, data_out, data_len);

		/* Close the key to free up the volatile slot. */
		status = al_psa_status(
			psa_close_key(key_handle),
			__func__);
		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to close persistent key.");
			goto err;
		}
	}

	return status;
err:
	al_dump_log();
	return status;
}
#endif /* CONFIG_PSA_IMPORT_KEY */

/**
 * @brief PSA Random number generator wrapper for Mbed TLS
 */
static int psa_rng_for_mbedtls(void *p_rng,
			       unsigned char *output, size_t output_len)
{
	(void)p_rng;

	return psa_generate_random(output, output_len);
}

/**
 * @brief Generates device certificate signing request (CSR) using Mbed TLS
 * X.509 and TF-M crypto service.
 */
psa_status_t crp_generate_csr(unsigned char* json_encoded_csr,
                                size_t json_encoded_csr_len)
{
	psa_status_t status;
	psa_key_id_t key_slot = 1;
	psa_key_handle_t key_handle;

	unsigned char output_buf[1024];
	unsigned char uuid[37];

	/* length of CSR subject name is calculated as
	 * strlen(O=Linaro,CN=) + UUID length + null character
	 * 12 + 37 + 1
	*/
	char csr_subject_name[50];

	mbedtls_pk_context pk_key_container;
	mbedtls_x509write_csr req;

	struct csr_json_struct csr_json = {
		.CSR = output_buf
	};

	status = al_psa_status(
		tfm_secure_provisioning_generate_uuid(uuid, sizeof(uuid)),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Unable to get UUID.");
		return;
	}

	strncpy(csr_subject_name, "O=Linaro,CN=", strlen("O=Linaro,CN="));
	strncpy(csr_subject_name+strlen("O=Linaro,CN="), uuid, sizeof(uuid));

	printf("csr_subject_name: %s\n", csr_subject_name);

	/* Initialize Mbed TLS structures. */
	mbedtls_x509write_csr_init(&req);
	mbedtls_pk_init(&pk_key_container);
	memset(output_buf, 0, sizeof(output_buf));

	/* Initialize crypto API. */
	LOG_INF("Initialising PSA crypto");
	al_dump_log();

	status = al_psa_status(psa_crypto_init(), __func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Crypto init failed.");
		goto err;
	}

	LOG_INF("PSA crypto init completed");
	al_dump_log();

	/* prime256v1 (ecdsa-with-SHA256) private key. */
#if CONFIG_PSA_IMPORT_KEY
#if CONFIG_PRIVATE_KEY_STATIC
	/* This value is based on the private key in user.pem,
	 * which can be viewed viw the following command:
	 *
	 *   $ openssl ec -in user.pem -text -noout
	 */
	uint8_t priv_key_data[32] = {
		0x14, 0xbc, 0xb9, 0x53, 0xa4, 0xee, 0xed, 0x50,
		0x09, 0x36, 0x92, 0x07, 0x1d, 0xdb, 0x24, 0x2c,
		0xef, 0xf9, 0x57, 0x92, 0x40, 0x4f, 0x49, 0xaa,
		0xd0, 0x7c, 0x5b, 0x3f, 0x26, 0xa7, 0x80, 0x48
	};
#else /* !CONFIG_PRIVATE_KEY_STATIC */
	/* Randomly generate the private key. */
	uint8_t priv_key_data[32] = { 0 };

	LOG_INF("Generate rnadom data for private key");
	al_dump_log();

	psa_generate_random(priv_key_data, sizeof(priv_key_data));
	LOG_INF("Random data generation for private key completed");
	al_dump_log();

#endif /* CONFIG_PRIVATE_KEY_STATIC */

	/* Generate persistent prime256v1 (ecdsa-with-SHA256) key w/ID #1. */
	/* PSA_KEY_USAGE_EXPORT can be added for debug purposes. */
	status = al_psa_status(
		crp_imp_key_secp256r1(key_slot,
				      PSA_KEY_USAGE_SIGN_HASH |
				      PSA_KEY_USAGE_VERIFY_HASH,
				      priv_key_data),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to create persistent key #%d", key_slot);
		goto err;
	}
#else /* !CONFIG_PSA_IMPORT_KEY */

	/* NOTE: The certificate signing request (CSR) can be generated using
	 * openssl by using following commands:
	 *
	 * Generate a new key:
	 *
	 *   $ openssl ecparam -name secp256k1 -genkey -out USER.key
	 *
	 * Generate a certificate signing request, containing the user public key
	 * and required details to be inserted into the user certificate.
	 * openssl req -new -key USER.key -out USER.csr \
	 *   -subj "/O=Linaro/CN=$(uuidgen | tr '[:upper:]' '[:lower:]')"
	 *
	 */

	/* Generate persistent prime256v1 (ecdsa-with-SHA256) key w/ID #1. */
	/* PSA_KEY_USAGE_EXPORT can be added for debug purposes. */
	status = al_psa_status(
		crp_gen_key_secp256r1(key_slot,
				      PSA_KEY_USAGE_SIGN_HASH |
				      PSA_KEY_USAGE_VERIFY_HASH),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to create persistent key #%d", key_slot);
		goto err;
	}
#endif /* CONFIG_PSA_IMPORT_KEY */

	status = al_psa_status(
		psa_open_key(key_slot, &key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to open persistent key #%d", key_slot);
		goto err;
	}

	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	psa_get_key_attributes(key_handle, &attributes);
	mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);

	LOG_INF("Adding subject name to CSR");
	al_dump_log();

	status = mbedtls_x509write_csr_set_subject_name(&req, csr_subject_name);
	if (status != 0) {
		LOG_ERR("failed! mbedtls_x509write_csr_set_subject_name returned %d", status);
		goto err;
	}

	LOG_INF("Adding subject name to CSR completed");
	al_dump_log();

	LOG_INF("Adding EC key to PK container");
	al_dump_log();

	status = mbedtls_pk_setup_opaque(&pk_key_container, key_handle);
	if (status != 0) {
		LOG_ERR("failed! mbedtls_pk_setup_opaque returned -0x%04x", (unsigned int) -status);
		goto err;
	}

	LOG_INF("Adding EC key to PK container completed");
	al_dump_log();

	mbedtls_x509write_csr_set_key(&req, &pk_key_container);

	LOG_INF("Create device Certificate Signing Request");
	al_dump_log();

	status = mbedtls_x509write_csr_pem(&req, output_buf, sizeof(output_buf),
					   psa_rng_for_mbedtls, NULL);
	if (status < 0) {
		LOG_ERR("failed! mbedtls_x509write_csr_pem returned -0x%04x",
			(unsigned int) -status);
		goto err;
	}

	LOG_INF("Create device Certificate Signing Request completed");
	al_dump_log();

	LOG_INF("Certificate Signing Request:\n");
	al_dump_log();

	printf("%s\n", output_buf);

	/*
	 * 1.3. Encoding CSR as JSON
	 */
	LOG_INF("Encoding CSR as json");
	al_dump_log();

	status = json_obj_encode_buf(csr_json_descr, ARRAY_SIZE(csr_json_descr),
				     &csr_json, json_encoded_csr, json_encoded_csr_len);

	if (status != 0) {
		LOG_ERR("failed! json_obj_encode_buf returned 0x%04x", status);
		goto err;
	}

	LOG_INF("Encoding CSR as json completed");
	al_dump_log();

	/* Close the key to free up the volatile slot. */
	status = al_psa_status(
		psa_close_key(key_handle),
		__func__);
	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to close persistent key.");
		goto err;
	}

err:
	al_dump_log();
	mbedtls_x509write_csr_free(&req);
	mbedtls_pk_free(&pk_key_container);

	return status;
}
