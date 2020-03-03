/*
*********************************************************************************************************
*                                               uC/DNSc
*                                     Domain Name Server (client)
*
*                    Copyright 2004-2020 Silicon Laboratories Inc. www.silabs.com
*
*                                 SPDX-License-Identifier: APACHE-2.0
*
*               This software is subject to an open source license and is distributed by
*                Silicon Laboratories Inc. pursuant to the terms of the Apache License,
*                    Version 2.0 available at www.apache.org/licenses/LICENSE-2.0.
*
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                       DNS CLIENT TASK MODULE
*
* Filename : dns-c_task.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) Assumes the following versions (or more recent) of software modules are included
*                in the project build :
*
*                (a) uC/Common-KAL V1.00.00
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#include  "dns-c_type.h"
#include  "dns-c_task.h"
#include  "dns-c_cache.h"
#include  "KAL/kal.h"


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

#ifdef  DNSc_TASK_MODULE_EN
       KAL_TASK_HANDLE  DNScTask_TaskHandle;
       KAL_SEM_HANDLE   DNScTask_SignalHandle;
#else
const  DNSc_CFG        *DNScTask_CfgPtr;
#endif


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

#ifdef  DNSc_TASK_MODULE_EN
static  void  DNScTask       (void  *p_arg);
#endif



/*
*********************************************************************************************************
*                                            DNScTask_Init()
*
* Description : Initialize DNSc task module.
*
* Argument(s) : p_cfg   Pointer to the DNSc configuration.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Successfully initialized
*                           DNSc_ERR_MEM_ALLOC      Memory allocation error.
*                           DNSc_ERR_FAULT_INIT     Fault during OS object initialization.
*
*
* Return(s)   : None.
*
* Caller(s)   : DNSc_Init().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : none.
*********************************************************************************************************
*/

void  DNScTask_Init (const  DNSc_CFG       *p_cfg,
                     const  DNSc_CFG_TASK  *p_task_cfg,
                            DNSc_ERR       *p_err)
{
#ifdef  DNSc_TASK_MODULE_EN
    void     *p_stack = DEF_NULL;
    KAL_ERR   kal_err;


#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_task_cfg == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }
#endif


    DNScTask_SignalHandle = KAL_SemCreate("DNSc Task Signal",
                                           DEF_NULL,
                                          &kal_err);
    switch (kal_err) {
        case KAL_ERR_NONE:
             break;

        case KAL_ERR_MEM_ALLOC:
            *p_err = DNSc_ERR_MEM_ALLOC;
             goto exit;

        default:
            *p_err = DNSc_ERR_FAULT_INIT;
             goto exit;
    }

    if (p_task_cfg->StkPtr != DEF_NULL) {
        p_stack = (void *)p_task_cfg->StkPtr;
    }

    DNScTask_TaskHandle = KAL_TaskAlloc("DNSc Task",
                                         p_stack,
                                         p_task_cfg->StkSizeBytes,
                                         DEF_NULL,
                                        &kal_err);
    switch (kal_err) {
        case KAL_ERR_NONE:
             break;

        case KAL_ERR_MEM_ALLOC:
            *p_err = DNSc_ERR_MEM_ALLOC;
             goto exit;

        default:
            *p_err = DNSc_ERR_FAULT_INIT;
             goto exit;
    }


    KAL_TaskCreate(DNScTask_TaskHandle,
                  &DNScTask,
           (void *)p_cfg,
                   p_task_cfg->Prio,
                   DEF_NULL,
                  &kal_err);
    switch (kal_err) {
        case KAL_ERR_NONE:
             break;

        case KAL_ERR_MEM_ALLOC:
            *p_err = DNSc_ERR_MEM_ALLOC;
             goto exit;

        default:
            *p_err = DNSc_ERR_FAULT_INIT;
             goto exit;
    }


   *p_err = DNSc_ERR_NONE;

exit:
#else
    DNScTask_CfgPtr = p_cfg;
#endif
    return;
}


/*
*********************************************************************************************************
*                                        DNScTask_ResolveHost()
*
* Description : Function to submit a host resolution to the task or to perform host resolution.
*
* Argument(s) : p_host  Pointer to the Host object.
*
*               flags   Request flag option
*
*               p_cfg   Request configuration.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE               Resolution submitted or completed.
*                           DNSc_ERR_TASK_SIGNAL
*
*                           RETURNED BY DNScCache_HostInsert():
*                               See DNScCache_HostInsert() for additional return error codes.
*
*                           RETURNED BY DNScCache_ProcessHost():
*                               See DNScCache_ProcessHost() for additional return error codes.
*
*
* Return(s)   : Resolution status:
*                       DNSc_STATUS_PENDING         Host resolution is pending, call again to see the status. (Processed by DNSc's task)
*                       DNSc_STATUS_RESOLVED        Host is resolved.
*                       DNSc_STATUS_FAILED          Host resolution has failed.
*
* Caller(s)   : DNSc_GetHost().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

DNSc_STATUS  DNScTask_HostResolve (DNSc_HOST_OBJ  *p_host,
                                   DNSc_FLAGS      flags,
                                   DNSc_REQ_CFG   *p_cfg,
                                   DNSc_ERR       *p_err)
{
#ifdef DNSc_TASK_MODULE_EN
    KAL_ERR      err;
#endif
    DNSc_STATUS  status = DNSc_STATUS_NONE;
    CPU_BOOLEAN  flag_set;


    flag_set = DEF_BIT_IS_SET(flags, DNSc_FLAG_REVERSE_LOOKUP);
    if (((flag_set                != DEF_TRUE)  &&
         (p_host->ReverseNamePtr  != DEF_NULL)) ||
         (p_host->AddrsCount      ==       0u)) {
        DNScCache_HostInsert(p_host, p_err);
        if (*p_err != DNSc_ERR_NONE) {
             goto exit;
        }
    }

#ifdef DNSc_TASK_MODULE_EN
    KAL_SemPost(DNScTask_SignalHandle, KAL_OPT_POST_NONE, &err);


#ifdef  DNSc_SIGNAL_TASK_MODULE_EN
    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_NO_BLOCK) == DEF_NO) {
        KAL_ERR  err_muck;


        status = DNSc_STATUS_UNKNOWN;
        KAL_SemPend(p_host->TaskSignal, KAL_OPT_PEND_BLOCKING, 0u, &err);
        KAL_SemDel(p_host->TaskSignal, &err_muck);
       (void)&err_muck;
        p_host->TaskSignal = KAL_SemHandleNull;
        if (err != KAL_ERR_NONE) {
            DNScCache_HostRemove(p_host);
           *p_err  = DNSc_ERR_TASK_SIGNAL;
            status = DNSc_STATUS_FAILED;
            goto exit;
        }

    } else {
        status = DNSc_STATUS_PENDING;
    }
#endif  /* DNSc_SIGNAL_TASK_MODULE_EN */

#else
    status = DNSc_STATUS_PENDING;
    while (status == DNSc_STATUS_PENDING) {
        CPU_INT16U  dly = DNScTask_CfgPtr->TaskDly_ms;


        if (p_cfg != DEF_NULL) {
            dly = p_cfg->TaskDly_ms;
        }


        status = DNScCache_ResolveHost(DNScTask_CfgPtr, p_host, p_err);

        KAL_Dly(dly);
    }

    if (status == DNSc_STATUS_FAILED) {
        DNScCache_HostRemove(p_host);
    }
#endif  /* DNSc_TASK_MODULE_EN */

exit:
    return (status);
}


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                              DNScTask()
*
* Description : DNSc's task.
*
* Argument(s) : p_arg   Pointer to task argument, should be the DNSc's configuration.
*
* Return(s)   : None.
*
* Caller(s)   : Referenced by DNScTask_Init().
*
* Note(s)     : None.
*********************************************************************************************************
*/
#ifdef  DNSc_TASK_MODULE_EN
static  void  DNScTask (void  *p_arg)
{
    const  DNSc_CFG    *p_cfg           = (const DNSc_CFG *)p_arg;
           CPU_INT16U   nb_req_active   =  0u;
           CPU_INT16U   nb_req_resolved =  0u;
           KAL_OPT      opt;
           KAL_ERR      kal_err;
           DNSc_ERR     dns_err;



    while (DEF_ON) {
        opt = KAL_OPT_PEND_NONE;
        if (nb_req_active > 0u) {
            DEF_BIT_SET(opt, KAL_OPT_PEND_NON_BLOCKING);
        }

        KAL_SemPend(DNScTask_SignalHandle, opt, 0, &kal_err);
        switch (kal_err) {
            case KAL_ERR_NONE:
                 nb_req_active++;
                 break;

            default:
                 break;
        }

        nb_req_resolved = DNScCache_ResolveAll(p_cfg, &dns_err);
        if (nb_req_resolved < nb_req_active) {
            nb_req_active  -= nb_req_resolved;
        } else {
            nb_req_active   = 0u;
        }

        KAL_Dly(p_cfg->TaskDly_ms);
    }
}
#endif
