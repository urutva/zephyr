/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>

#include "psa/crypto.h"
#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generates device certificate signing request (CSR) using Mbed TLS
 * X.509 and TF-M crypto service.
 */
psa_status_t crp_generate_csr(unsigned char* json_encoded_csr,
                                size_t json_encoded_csr_len);

#ifdef __cplusplus
}
#endif
