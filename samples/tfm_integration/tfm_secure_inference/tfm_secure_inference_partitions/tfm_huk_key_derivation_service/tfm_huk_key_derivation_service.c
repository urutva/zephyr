/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <psa/crypto.h>
#include <stdbool.h>
#include <stdint.h>
#include "tfm_secure_api.h"
#include "tfm_api.h"

#include "log/tfm_log.h"
#include "tfm_crypto_defs.h"
#include "psa/crypto.h"
#include "psa/service.h"
#include "psa_manifest/tfm_huk_key_derivation_service.h"

#define KEY_LEN_BYTES  16

typedef psa_status_t (*signal_handler_t)(psa_msg_t *);

static psa_status_t tfm_huk_key_derivation(psa_msg_t *msg)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	uint8_t *uuid_label = "UUID";
	uint8_t uuid[16];
	psa_key_id_t uuid_key;
	size_t uuid_length;

	/* Set the key attributes for the key */
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT |
				PSA_KEY_USAGE_DECRYPT |
				PSA_KEY_USAGE_EXPORT);

	psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(KEY_LEN_BYTES));

	/* Set up a key derivation operation with HUK derivation as the alg */
	status = psa_key_derivation_setup(&op, TFM_CRYPTO_ALG_HUK_DERIVATION);
	if (status != PSA_SUCCESS) {
		return status;
	}

	/* Supply the UUID label as an input to the key derivation */
	status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_LABEL,
						uuid_label,
						sizeof(uuid_label));
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	/* Create the storage key from the key derivation operation */
	status = psa_key_derivation_output_key(&attributes, &op, &uuid_key);
	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	// status = psa_key_derivation_output_bytes(&op, uuid, sizeof(uuid));

	status =  psa_export_key(uuid_key, uuid, sizeof(uuid), &uuid_length);

	if (status != PSA_SUCCESS) {
		goto err_release_op;
	}

	/* Free resources associated with the key derivation operation */
	status = psa_key_derivation_abort(&op);
	if (status != PSA_SUCCESS) {
		return status;
	}

	psa_write(msg->handle, 0, uuid, uuid_length);

	return PSA_SUCCESS;

err_release_op:
	(void)psa_key_derivation_abort(&op);

	return status;
}


static void tfm_huk_key_derivation_signal_handle(psa_signal_t signal, signal_handler_t pfn)
{
	psa_status_t status;
	psa_msg_t msg;

	status = psa_get(signal, &msg);
	switch (msg.type) {
	case PSA_IPC_CONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	case PSA_IPC_CALL:
		status = pfn(&msg);
		psa_reply(msg.handle, status);
		break;
	case PSA_IPC_DISCONNECT:
		psa_reply(msg.handle, PSA_SUCCESS);
		break;
	default:
		psa_panic();
	}
}

psa_status_t tfm_huk_key_derivation_req_mngr_init(void)
{
	psa_signal_t signals = 0;

	while (1) {
		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
		if (signals & TFM_HUK_KEY_DERIVATION_SIGNAL) {
			tfm_huk_key_derivation_signal_handle(TFM_HUK_KEY_DERIVATION_SIGNAL,
							      tfm_huk_key_derivation);
		} else {
			psa_panic();
		}
	}

	return PSA_SUCCESS;
}
