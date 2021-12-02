#
# Copyright (c) 2021 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_app_rot_partition_huk_key_derivation STATIC)

target_include_directories(tfm_app_rot_partition_huk_key_derivation
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/tfm_secure_inference/tfm_secure_inference_partitions/tfm_huk_key_derivation_service
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/tfm_secure_inference/tfm_secure_inference_partitions/tfm_huk_key_derivation_service
)

target_sources(tfm_app_rot_partition_huk_key_derivation
    PRIVATE
        tfm_huk_key_derivation_service
)

# The generated sources
target_sources(tfm_app_rot_partition_huk_key_derivation
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/generated/tfm_secure_inference/tfm_secure_inference_partitions/tfm_huk_key_derivation_service/auto_generated/intermedia_tfm_huk_key_derivation_service.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/generated/tfm_secure_inference/tfm_secure_inference_partitions/tfm_huk_key_derivation_service/auto_generated/load_info_tfm_huk_key_derivation_service.c>
)

target_link_libraries(tfm_app_rot_partition_huk_key_derivation
    PRIVATE
        tfm_secure_api
        psa_interface
        secure_fw
        platform_s
        tfm_psa_rot_partition_crypto
)

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_huk_key_derivation
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_HUK_KEY_DERIVATION
)
