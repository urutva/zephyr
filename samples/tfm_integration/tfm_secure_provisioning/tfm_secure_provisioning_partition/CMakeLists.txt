#
# Copyright (c) 2021 Linaro Limited
#
# SPDX-License-Identifier: Apache-2.0
#

add_library(tfm_app_rot_partition_secure_provision STATIC)

target_include_directories(tfm_app_rot_partition_secure_provision
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/tfm_secure_provisioning/tfm_secure_provisioning_partition
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/tfm_secure_provisioning/tfm_secure_provisioning_partition
)

target_sources(tfm_app_rot_partition_secure_provision
    PRIVATE
        tfm_secure_provisioning_partition
)

# The generated sources
target_sources(tfm_app_rot_partition_secure_provision
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/generated/tfm_secure_provisioning/tfm_secure_provisioning_partition/auto_generated/intermedia_tfm_secure_provisioning_partition.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/generated/tfm_secure_provisioning/tfm_secure_provisioning_partition/auto_generated/load_info_tfm_secure_provisioning_partition.c>
)

target_link_libraries(tfm_app_rot_partition_secure_provision
    PRIVATE
        tfm_secure_api
        psa_interface
        secure_fw
        platform_s
        tfm_psa_rot_partition_crypto
)

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_secure_provision
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_SECURE_PROVISIONING
)
