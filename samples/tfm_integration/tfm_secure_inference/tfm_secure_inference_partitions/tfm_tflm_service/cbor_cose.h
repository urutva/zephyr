/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __CBOR_COSE_H__
#define __CBOR_COSE_H__

#include <stdint.h>
#include "qcbor.h"
#include "t_cose_sign1_sign.h"
#include "t_cose_sign1_verify.h"

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Key handle for EC key used for COSE */
extern psa_key_handle_t tflm_cose_key_handle;

/**
 * The context for encoding inference value.  The caller of
 * tflm_inference_value_encode_and_sign must create one of these and
 * pass it to the functions here. It is small enough that it can go
 * on the stack. It is most of the memory needed to create a token
 * except the output buffer and any memory requirements for the
 * cryptographic operations.
 *
 * The structure is opaque for the caller.
 *
 * This is roughly 148 + 32 = 180 bytes
 */
struct tflm_inf_val_encode_ctx {
	/* Private data structure */
	QCBOREncodeContext cbor_enc_ctx;
	struct t_cose_sign1_sign_ctx signer_ctx;
};

/* Labels for CBOR encoding */
#define EAT_CBOR_LINARO_RANGE_BASE                  (-80000)
#define EAT_CBOR_LINARO_LABEL_INFERENCE_VALUE       (EAT_CBOR_LINARO_RANGE_BASE - 0)

#ifdef __cplusplus
}
#endif

#endif /* __CBOR_COSE_H__ */
