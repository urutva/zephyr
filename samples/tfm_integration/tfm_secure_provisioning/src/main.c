/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr.h>
#include <tfm_veneers.h>
#include <tfm_ns_interface.h>

#include "psa_crypto.h"
#include "tfm_secure_provisioning_api.h"

void main(void)
{
	/* Generate Certificate Signing Request using Mbed TLS */
	crp_generate_csr();
}
