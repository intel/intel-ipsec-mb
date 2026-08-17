/*******************************************************************************
  Copyright (c) 2020-2024, Intel Corporation

  SPDX-License-Identifier: BSD-3-Clause
*******************************************************************************/

#ifndef ERROR_H
#define ERROR_H

#include "mb_mgr.h"

/*
 * declare global variable to store
 * process wide error status
 */
extern volatile int imb_errno;

/**
 * @brief API to set error status
 *
 * @param mb_mgr Pointer to multi-buffer manager
 * @param errnum Error type
 */
__forceinline void
imb_set_errno(IMB_MGR *mb_mgr, const int errnum)
{
        /* set MB_MGR error status */
        if (mb_mgr != NULL)
                mb_mgr->imb_errno = errnum;

        /*
         * set global error status
         * (only if different, to limit unneeded stores)
         */
        if (imb_errno != errnum)
                imb_errno = errnum;
}

#endif /* ERROR_H */
