#ifndef __FIRMWARE_BLOB_H
#define __FIRMWARE_BLOB_H

#include <linux/types.h>

enum sw_type_t
{
	SW_TYPE_RECOVERY,
	SW_TYPE_RELEASE,
	SW_TYPE_TESTING,
	SW_TYPE_DEVELOPMENT,
	SW_TYPE_COUNT,
};

struct blob_header
{
	uint32_t magic;
	uint32_t blob_size;
	uint32_t package_identifier_len;
	uint32_t bitstream_len;
	uint32_t elf_len;
	uint32_t project_id;
	uint32_t sw_type;
} __attribute__((__packed__));
typedef enum
{
	VALIDATE_BLOB_ERR_NONE,
	VALIDATE_BLOB_ERR_INTEGRITY_VERIFICATION_FAILED,
	VALIDATE_BLOB_ERR_INTEGRITY_UNALIGNED_BLOB,
	VALIDATE_BLOB_ERR_INTEGRITY_INVALID_MAGIC,
	VALIDATE_BLOB_ERR_INTEGRITY_INVALID_BLOB_LEN,
	VALIDATE_BLOB_ERR_INTEGRITY_TOO_MANY_SIG_BYTES,
	VALIDATE_BLOB_ERR_INTEGRITY_MALFORMED_SIG,
	VALIDATE_BLOB_ERR_INVALID_SW_TYPE,
	VALIDATE_BLOB_ERR_PROJECT_ID_MISMATCH,
	VALIDATE_BLOB_ERR_UNAUTHORIZED_SW_TYPE,
	VALIDATE_BLOB_ERR_BOARD_PARTITION_MISMATCH,
	VALIDATE_BLOB_ERR_SIGNATURE_MISSING_WHEN_REQUIRED,
	VALIDATE_BLOB_ERR_INTERNAL,
	VALIDATE_BLOB_ERR_COUNT,
} validate_blob_err_t;

typedef enum
{
	BOARD_PARTITION_NONE,
	BOARD_PARTITION_RECOVERY,
	BOARD_PARTITION_SOFTWARE,
	BOARD_PARTITION_COUNT,
} board_partition_t;

struct validate_blob_input
{
	const void *blob;
	uint32_t blob_len;
	board_boot_policy_t board_boot_policy;
	uint32_t board_project_id;
	board_partition_t board_partition;
};

validate_blob_err_t validate_blob(const struct validate_blob_input *validate_blob_input, const char **feedback);

#endif // __FIRMWARE_BLOB_H
