#
# Copyright (c) 2021 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

configure_file(
  ${CMAKE_CURRENT_LIST_DIR}/tfm_secure_provisioning_partition/tfm_manifest_list.yaml.in
  ${CMAKE_CURRENT_BINARY_DIR}/tfm_secure_provisioning_partition/tfm_manifest_list.yaml)

set_property(TARGET zephyr_property_target
  APPEND PROPERTY TFM_CMAKE_OPTIONS
  -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/tfm_secure_provisioning_partition/tfm_manifest_list.yaml
  -DTFM_EXTRA_PARTITION_PATHS=${CMAKE_CURRENT_LIST_DIR}/tfm_secure_provisioning_partition
  )

project(tfm_secure_provisioning)

target_sources(app
                PRIVATE
                src/main.c
                src/psa_crypto.c
                src/util_app_log.c
                src/util_sformat.c
                src/tfm_secure_provisioning_api.c
                src/http.c)

target_include_directories(app PRIVATE
  ${ZEPHYR_TRUSTED_FIRMWARE_M_MODULE_DIR}/interface/include
)

target_compile_definitions(app
    PRIVATE TFM_PARTITION_SECURE_PROVISIONING)

# In TF-M, default value of CRYPTO_ENGINE_BUF_SIZE is 0x2080. It causes
# insufficient memory failure while verifying signature. Increase it to 0x2400.
set_property(TARGET zephyr_property_target
             APPEND PROPERTY TFM_CMAKE_OPTIONS
             -DCRYPTO_ENGINE_BUF_SIZE=0x2400
)

zephyr_include_directories(${APPLICATION_SOURCE_DIR}/src/tls_config)
