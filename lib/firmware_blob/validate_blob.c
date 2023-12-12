// SPDX-License-Identifier: GPL-2.0+
/*
 * Firmware Blob Library - for parsing and verification of Zynq FW blobs
 *
 * Copyright (c) 2023 - Cegelec a.s.
 */

#include "firmware_blob.h"
#include "validate_blob.h"
#include "verify_blob_integrity.h"

#include <stdint.h>
#include <string.h>

static const char *const validate_blob_err_feedback[VALIDATE_BLOB_ERR_COUNT] = {
    [VALIDATE_BLOB_ERR_NONE] = NULL,
    [VALIDATE_BLOB_ERR_INTEGRITY_VERIFICATION_FAILED] =
        "verification of blob signature failed",
    [VALIDATE_BLOB_ERR_INTEGRITY_UNALIGNED_BLOB] =
        "blob is not aligned to 4-byte boundary",
    [VALIDATE_BLOB_ERR_INTEGRITY_INVALID_MAGIC] =
        "invalid magic at start of blob",
    [VALIDATE_BLOB_ERR_INTEGRITY_INVALID_BLOB_LEN] =
        "invalid blob size, blob appears to be truncated",
    [VALIDATE_BLOB_ERR_INTEGRITY_TOO_MANY_SIG_BYTES] =
        "unsupported blob signature size",
    [VALIDATE_BLOB_ERR_INTEGRITY_MALFORMED_SIG] = "blob signature is malformed",
    [VALIDATE_BLOB_ERR_INVALID_SW_TYPE] = "invalid SW type in blob header",
    [VALIDATE_BLOB_ERR_PROJECT_ID_MISMATCH] = "incompatible project ID",
    [VALIDATE_BLOB_ERR_UNAUTHORIZED_SW_TYPE] =
        "unauthorized SW type for board boot policy",
    [VALIDATE_BLOB_ERR_BOARD_PARTITION_MISMATCH] =
        "incorrect SW type for board partition",
    [VALIDATE_BLOB_ERR_SIGNATURE_MISSING_WHEN_REQUIRED] =
        "SW signature is missing and required by board boot policy",
    [VALIDATE_BLOB_ERR_INTERNAL] =
        "internal error occured in blob validation library",
};

struct authorization_record
{
  int allow;
  int allow_skip_signature_check;
  int allow_skip_project_id_check;
  board_partition_t board_partition;
};

static const struct authorization_record
    boot_policy_sw_type_authorization_matrix
        [BOARD_BOOT_POLICY_COUNT][SW_TYPE_COUNT] = {

            [BOARD_BOOT_POLICY_NOT_SET] =
                {
                    [SW_TYPE_RECOVERY] =
                        {
                            .allow = 0,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_NONE,
                        },
                    [SW_TYPE_RELEASE] =
                        {
                            .allow = 0,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_NONE,
                        },
                    [SW_TYPE_TESTING] =
                        {
                            .allow = 0,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_NONE,
                        },
                    [SW_TYPE_DEVELOPMENT] =
                        {
                            .allow = 0,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_NONE,
                        },
                },

            [BOARD_BOOT_POLICY_PRODUCTION] =
                {
                    [SW_TYPE_RECOVERY] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_RECOVERY,
                        },
                    [SW_TYPE_RELEASE] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_TESTING] =
                        {
                            .allow = 0,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_NONE,
                        },
                    [SW_TYPE_DEVELOPMENT] =
                        {
                            .allow = 0,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_NONE,
                        },
                },

            [BOARD_BOOT_POLICY_SIGNED] =
                {
                    [SW_TYPE_RECOVERY] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_RECOVERY,
                        },
                    [SW_TYPE_RELEASE] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_TESTING] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_DEVELOPMENT] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                },

            [BOARD_BOOT_POLICY_DEVELOPMENT_PROJECT_ID] =
                {
                    [SW_TYPE_RECOVERY] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_RECOVERY,
                        },
                    [SW_TYPE_RELEASE] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 1,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_TESTING] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 1,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_DEVELOPMENT] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 1,
                            .allow_skip_project_id_check = 0,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                },

            [BOARD_BOOT_POLICY_DEVELOPMENT] =
                {
                    [SW_TYPE_RECOVERY] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 0,
                            .allow_skip_project_id_check = 1,
                            .board_partition = BOARD_PARTITION_RECOVERY,
                        },
                    [SW_TYPE_RELEASE] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 1,
                            .allow_skip_project_id_check = 1,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_TESTING] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 1,
                            .allow_skip_project_id_check = 1,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                    [SW_TYPE_DEVELOPMENT] =
                        {
                            .allow = 1,
                            .allow_skip_signature_check = 1,
                            .allow_skip_project_id_check = 1,
                            .board_partition = BOARD_PARTITION_SOFTWARE,
                        },
                },
};

validate_blob_err_t
validate_blob(const struct validate_blob_input *validate_blob_input,
              const char **feedback)
{
  validate_blob_err_t ret = 0;

  if (validate_blob_input->board_boot_policy >= BOARD_BOOT_POLICY_COUNT ||
      validate_blob_input->board_partition >= BOARD_PARTITION_COUNT) {
    ret = VALIDATE_BLOB_ERR_INTERNAL;
    goto out;
  }

  struct blob_header blob_header;
  int has_valid_signature = 0;
  ret = verify_blob_integrity(validate_blob_input->blob,
                              validate_blob_input->blob_len, &blob_header,
                              &has_valid_signature);
  if (ret != 0)
    goto out;

  if (blob_header.sw_type >= SW_TYPE_COUNT) {
    ret = VALIDATE_BLOB_ERR_INVALID_SW_TYPE;
    goto out;
  }

  const struct authorization_record *authorization_record =
      &boot_policy_sw_type_authorization_matrix
          [validate_blob_input->board_boot_policy][blob_header.sw_type];

  if (authorization_record->allow != 1) {
    ret = VALIDATE_BLOB_ERR_UNAUTHORIZED_SW_TYPE;
    goto out;
  }

  if (authorization_record->board_partition !=
      validate_blob_input->board_partition) {
    ret = VALIDATE_BLOB_ERR_BOARD_PARTITION_MISMATCH;
    goto out;
  }

  if (has_valid_signature != 1 &&
      authorization_record->allow_skip_signature_check != 1) {
    ret = VALIDATE_BLOB_ERR_SIGNATURE_MISSING_WHEN_REQUIRED;
    goto out;
  }

  if (blob_header.project_id != validate_blob_input->board_project_id &&
      authorization_record->allow_skip_project_id_check != 1) {
    ret = VALIDATE_BLOB_ERR_PROJECT_ID_MISMATCH;
    goto out;
  }

out:
  if (feedback) {
    *feedback = validate_blob_err_feedback[ret];
  }

  return ret;
}