/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tfm_huk_key_derivation_service_api.h"

psa_status_t tfm_huk_key_derivation(void *uuid,
				    size_t uuid_size)
{
	psa_status_t status;
	psa_handle_t handle;

	psa_outvec out_vec[] = {
		{ .base = uuid, .len = uuid_size }
	};

	handle = psa_connect(TFM_HUK_KEY_DERIVATION_SID,
			     TFM_HUK_KEY_DERIVATION_VERSION);
	if (!PSA_HANDLE_IS_VALID(handle)) {
		return PSA_ERROR_GENERIC_ERROR;
	}

	status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, IOVEC_LEN(out_vec));

	psa_close(handle);

	return status;
}
