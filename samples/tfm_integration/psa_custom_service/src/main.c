/*
 * Copyright (c) 2021 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <logging/log_ctrl.h>
#include <logging/log.h>

#include "tfm_example_partition_api.h"
#include "util_app_log.h"
#include "util_sformat.h"

/** Declare a reference to the application logging interface. */
LOG_MODULE_DECLARE(app, CONFIG_LOG_DEFAULT_LEVEL);

struct sf_hex_tbl_fmt main_fmt = {
	.ascii = true,
	.addr_label = true,
	.addr = 0
};

void main(void)
{
	/* Message to be hashed */
	uint8_t input[] = "Please hash this message.";
	uint8_t hash[PSA_HASH_SIZE(PSA_ALG_SHA_256)] = { 0 };
	size_t hash_len;
	psa_status_t status;
	uint8_t lsm303_data[6] = {0};

	/* Initialise the logger subsys and dump the current buffer. */
	log_init();

	LOG_INF("Hashing the message");
	al_dump_log();

	/* Display the message */
	sf_hex_tabulate_16(&main_fmt, input, strlen(input));

	status = al_psa_status(
		psa_example_hash(input,
						 strlen(input),
						 hash,
						 sizeof(hash),
						 &hash_len),
		__func__);

	if (status != PSA_SUCCESS) {
		LOG_ERR("Failed to compute SHA-256 hash");
		goto err;
	}

	LOG_INF("Size of SHA-256 hash is %d bytes", hash_len);
	al_dump_log();

	/* Display the SHA-256 hash */
	sf_hex_tabulate_16(&main_fmt, hash, (size_t)(PSA_HASH_SIZE(PSA_ALG_SHA_256)));

	while(true) {
		LOG_INF("Reading LSM303");
		al_dump_log();

		status = al_psa_status(
			example_read_lsm303(lsm303_data,
								sizeof(lsm303_data)),
			__func__);

		if (status != PSA_SUCCESS) {
			LOG_ERR("Failed to get values from LSM303");
			goto err;
		}

		LOG_INF("LSM303 magnetometer values: ");
		LOG_INF("mag_x: %x", (uint16_t)((lsm303_data[0] << 8) | lsm303_data[1]));
		LOG_INF("mag_y: %x", (uint16_t)((lsm303_data[4] << 8) | lsm303_data[5]));
		LOG_INF("mag_z: %x", (uint16_t)((lsm303_data[2] << 8) | lsm303_data[3]));

		k_msleep(2000);
	}

err:
	/* Dump any queued log messages, and wait for system events. */
	al_dump_log();
}
