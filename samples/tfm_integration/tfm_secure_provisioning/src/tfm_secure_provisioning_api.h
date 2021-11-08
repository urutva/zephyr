/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include "psa/client.h"
#include "psa_manifest/sid.h"

/**
 * \brief Generate UUID
 *
 * Generates an UUID based on https://datatracker.ietf.org/doc/html/rfc4122#section-4.4
 *
 * \param[in,out] uuid          Buffer to write UUID
 * \param[in] uuid_size         Size of UUID buffer
 *
 * \return A status indicating the success/failure of the operation
 */
psa_status_t tfm_secure_provisioning_generate_uuid(void *uuid,
						   size_t uuid_size);
