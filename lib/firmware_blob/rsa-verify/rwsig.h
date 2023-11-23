#ifndef VBOOT_RWSIG_H
#define VBOOT_RWSIG_H

#include "rsa.h"
#include "vb21_struct.h"

int rsa_check_signature(
	const uint8_t *rwdata,			  // Address of image
	unsigned int rwlen,				  // Length of image
	const struct rsa_public_key *key, // Key
	const uint8_t *sig				  // Signature of image
);

int vblock_check_signature(
	const uint8_t *rwdata,
	const struct vb21_packed_key *vb21_key,
	const struct vb21_signature *vb21_sig);

#endif // VBOOT_RWSIG_H