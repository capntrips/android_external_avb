/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if !defined(AVB_INSIDE_LIBAVB_AFTL_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb_aftl/libavb_aftl.h."
#endif

#ifndef AVB_AFTL_VALIDATE_H_
#define AVB_AFTL_VALIDATE_H_

#include <libavb/libavb.h>
#include "avb_aftl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Verifies that the logged vbmeta hash matches the one on device. */
bool avb_aftl_verify_vbmeta_hash(
    uint8_t* vbmeta,          /* Buffer containing the vbmeta data. */
    size_t vbmeta_size,       /* Size of the vbmeta buffer. */
    AftlIcpEntry* icp_entry); /* Pointer to the AftlIcpEntry to verify. */

/* Verifies the Merkle tree root hash. */
bool avb_aftl_verify_icp_root_hash(
    AftlIcpEntry* icp_entry); /* Pointer to the AftlIcpEntry to verify. */

/* Verifies the log root signature for the transparency log submission. */
bool avb_aftl_verify_entry_signature(
    const uint8_t* key,       /* Transparency log public key data. */
    size_t key_num_bytes,     /* Size of the key data. */
    AftlIcpEntry* icp_entry); /* Pointer to the AftlIcpEntry to verify. */

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_VALIDATE_H_ */
