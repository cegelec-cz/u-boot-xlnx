#ifndef FIRMWARE_BLOB_VERIFY_BLOB_INTEGRITY_H
#define FIRMWARE_BLOB_VERIFY_BLOB_INTEGRITY_H

#include "firmware_blob.h"

validate_blob_err_t
verify_blob_integrity(const void *blob, uint32_t blob_len,
                      struct blob_header *parsed_blob_header_out,
                      int *has_valid_signature);

#endif // FIRMWARE_BLOB_VERIFY_BLOB_INTEGRITY_H
