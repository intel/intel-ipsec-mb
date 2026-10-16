/*******************************************************************************
  Copyright (c) 2018-2026, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/
#include "intel-ipsec-mb.h"

/* Set library version */
#ifdef IMB_GIT_COMMIT
const char *imb_version_str = IMB_VERSION_STR " (" IMB_GIT_COMMIT ")";
#else
const char *imb_version_str = IMB_VERSION_STR;
#endif
const unsigned imb_version = IMB_VERSION_NUM;

const char *
imb_get_version_str(void)
{
        return imb_version_str;
}

unsigned
imb_get_version(void)
{
        return imb_version;
}
