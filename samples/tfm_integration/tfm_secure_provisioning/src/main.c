/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>

#include <tfm_veneers.h>
#include <tfm_ns_interface.h>

#include "psa_crypto.h"
#include "tfm_secure_provisioning_api.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

void main(void)
{
	unsigned char json_encoded_csr[1024];

	/* Generate Certificate Signing Request using Mbed TLS */
	crp_generate_csr(json_encoded_csr, sizeof(json_encoded_csr));

	LOG_INF("Certificate Signing Request in JSON:\n");
	al_dump_log();

	printf("%s\n", json_encoded_csr);

	send_http_post(json_encoded_csr);
}
