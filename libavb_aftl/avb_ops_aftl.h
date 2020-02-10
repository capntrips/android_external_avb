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

#ifndef AVB_AFTL_OPS_H_
#define AVB_AFTL_OPS_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

struct AvbAftlOps;
typedef struct AvbAftlOps AvbAftlOps;

/* An extension to AvbOps required by the new AFTL validation flow.
   TODO(danielaustin): update the AFTL readme link once it is submitted.  */
struct AvbAftlOps {
  /* Operations from libavb. */
  AvbOps* ops;
};

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_OPS_H_ */
