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
void crp_generate_csr(void);

#ifdef __cplusplus
}
#endif
