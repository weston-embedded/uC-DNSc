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
*                                       DNS CLIENT CACHE MODULE
*
* Filename : dns-c_cache.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) This file implements a basic DNS client based on RFC #1035.  It provides the
*                mechanism used to retrieve an IP address from a given host name.
*
*            (2) Assumes the following versions (or more recent) of software modules are included
*                in the project build :
*
*                (a) uC/LIB V1.37
*                (b) uC/Common-KAL V1.00.00
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#include  "dns-c_cache.h"
#include  "dns-c_req.h"
#include  <Source/net_ascii.h>
#include  <Source/net_util.h>
#include  <IF/net_if.h>
#include  <lib_mem.h>


/*
*********************************************************************************************************
*********************************************************************************************************
*                                              DATA TYPES
*********************************************************************************************************
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

static  KAL_LOCK_HANDLE   DNScCache_LockHandle;
static  MEM_DYN_POOL      DNScCache_ItemPool;
static  MEM_DYN_POOL      DNScCache_HostObjPool;
static  MEM_DYN_POOL      DNScCache_HostNamePool;
static  MEM_DYN_POOL      DNScCache_HostRevNamePool;
static  MEM_DYN_POOL      DNScCache_HostCanonNamePool;
static  MEM_DYN_POOL      DNScCache_AddrItemPool;
static  MEM_DYN_POOL      DNScCache_AddrObjPool;
static  MEM_DYN_POOL      DNScCache_ReqCfgPool;
static  DNSc_CACHE_ITEM  *DNSc_CacheItemListHead;


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

static  void              DNScCache_LockAcquire      (       DNSc_ERR         *p_err);

static  void              DNScCache_LockRelease      (       void);


static  void              DNScCache_HostRemoveHandler(       DNSc_HOST_OBJ    *p_host);

static  void              DNScCache_HostObjNameSet   (       DNSc_HOST_OBJ    *p_host,
                                                      const  CPU_CHAR         *p_host_name,
                                                             DNSc_ERR         *p_err);

static  DNSc_HOST_OBJ    *DNScCache_HostSrchByName   (const  CPU_CHAR         *p_host_name,
                                                             DNSc_FLAGS        flags);

static  CPU_BOOLEAN       DNScCache_HostNameCmp      (       DNSc_HOST_OBJ    *p_host,
                                                      const  CPU_CHAR         *p_host_name,
                                                             DNSc_FLAGS        flags);

static  DNSc_CACHE_ITEM  *DNScCache_ItemGet          (       DNSc_ERR         *p_err);

static  void              DNScCache_ItemFree         (       DNSc_CACHE_ITEM  *p_cache);

static  DNSc_HOST_OBJ    *DNScCache_ItemHostGet      (       void);

static  void              DNScCache_ItemRelease      (       DNSc_CACHE_ITEM  *p_cache);

static  void              DNScCache_ItemRemove       (       DNSc_CACHE_ITEM  *p_cache);

static  DNSc_ADDR_ITEM   *DNScCache_AddrItemGet      (       DNSc_ERR         *p_err);

static  void              DNScCache_AddrItemFree     (       DNSc_ADDR_ITEM   *p_item);

static  void              DNScCache_HostRelease      (       DNSc_HOST_OBJ    *p_host);

static  void              DNScCache_HostAddrClr      (       DNSc_HOST_OBJ    *p_host);

static  DNSc_STATUS       DNScCache_Resolve          (const  DNSc_CFG         *p_cfg,
                                                             DNSc_HOST_OBJ    *p_host,
                                                             DNSc_ERR         *p_err);

static  void              DNScCache_Req              (       DNSc_HOST_OBJ    *p_host,
                                                             DNSc_ERR         *p_err);

static  DNSc_STATUS       DNScCache_Resp             (const  DNSc_CFG         *p_cfg,
                                                             DNSc_HOST_OBJ    *p_host,
                                                             DNSc_ERR         *p_err);


/*
*********************************************************************************************************
*                                           DNScCache_Init()
*
* Description : Initialize cache module.
*
* Argument(s) : p_cfg   Pointer to DNSc's configuration.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Cache module successfully initialized.
*                           DNSc_ERR_MEM_ALLOC      Memory allocation error.
*                           DNSc_ERR_FAULT_INIT     Fault during OS object initialization.
*
* Return(s)   : None.
*
* Caller(s)   : DNSc_Init().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_Init (const  DNSc_CFG  *p_cfg,
                             DNSc_ERR  *p_err)
{
    CPU_SIZE_T  nb_addr;
    LIB_ERR     err;
    KAL_ERR     kal_err;


    DNScCache_LockHandle = KAL_LockCreate("DNSc Lock",
                                           KAL_OPT_CREATE_NONE,
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


    Mem_DynPoolCreate("DNSc Cache Item Pool",
                      &DNScCache_ItemPool,
                       p_cfg->MemSegPtr,
                       sizeof(DNSc_CACHE_ITEM),
                       sizeof(CPU_ALIGN),
                       1u,
                       p_cfg->CacheEntriesMaxNbr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    DNSc_CacheItemListHead = DEF_NULL;


    Mem_DynPoolCreate("DNSc Cache Host Obj Pool",
                      &DNScCache_HostObjPool,
                       p_cfg->MemSegPtr,
                       sizeof(DNSc_HOST_OBJ),
                       sizeof(CPU_ALIGN),
                       1u,
                       p_cfg->CacheEntriesMaxNbr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    Mem_DynPoolCreate("DNSc Cache Host Name Pool",
                      &DNScCache_HostNamePool,
                       p_cfg->MemSegPtr,
                       p_cfg->HostNameLenMax,
                       sizeof(CPU_ALIGN),
                       1u,
                       p_cfg->CacheEntriesMaxNbr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    Mem_DynPoolCreate("DNSc Cache Host Reverse Name Pool",
                      &DNScCache_HostRevNamePool,
                       p_cfg->MemSegPtr,
                       p_cfg->HostNameLenMax,
                       sizeof(CPU_ALIGN),
                       1u,
                       p_cfg->CacheEntriesMaxNbr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    Mem_DynPoolCreate("DNSc Cache Host Canonical Name Pool",
                      &DNScCache_HostCanonNamePool,
                       p_cfg->MemSegPtr,
                       p_cfg->HostNameLenMax,
                       sizeof(CPU_ALIGN),
                       1u,
                       p_cfg->CacheEntriesMaxNbr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    nb_addr = 0u;
#ifdef  NET_IPv4_MODULE_EN
    nb_addr += p_cfg->AddrIPv4MaxPerHost;
#endif
#ifdef  NET_IPv6_MODULE_EN
    nb_addr += p_cfg->AddrIPv6MaxPerHost;
#endif
    nb_addr *= p_cfg->CacheEntriesMaxNbr;

    Mem_DynPoolCreate("DNSc Cache Addr Item Pool",
                      &DNScCache_AddrItemPool,
                       p_cfg->MemSegPtr,
                       sizeof(DNSc_ADDR_ITEM),
                       sizeof(CPU_ALIGN),
                       1u,
                       nb_addr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    nb_addr++;

    Mem_DynPoolCreate("DNSc Cache Addr Obj Pool",
                      &DNScCache_AddrObjPool,
                       p_cfg->MemSegPtr,
                       sizeof(DNSc_ADDR_OBJ),
                       sizeof(CPU_ALIGN),
                       1u,
                       nb_addr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    Mem_DynPoolCreate("DNSc Cache Req Cfg Pool",
                      &DNScCache_ReqCfgPool,
                       p_cfg->MemSegPtr,
                       sizeof(DNSc_REQ_CFG),
                       sizeof(CPU_ALIGN),
                       1u,
                       p_cfg->CacheEntriesMaxNbr,
                      &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }


   *p_err = DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                            DNScCache_Clr()
*
* Description : Clear all elements of the cache.
*
* Argument(s) : p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE   Cache successfully cleared.
*
*                           RETURNED BY DNScCache_LockAcquire():
*                               See DNScCache_LockAcquire() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : DNSc_CacheClrAll().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_Clr (DNSc_ERR  *p_err)
{
    DNSc_CACHE_ITEM  *p_cache = DNSc_CacheItemListHead;
    DNSc_CACHE_ITEM  *p_cache_next;


    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }


    while (p_cache != DEF_NULL) {
        p_cache_next = p_cache->NextPtr;
        switch (p_cache->HostPtr->State) {
            case DNSc_STATE_INIT_REQ:
            case DNSc_STATE_TX_REQ_IPv4:
            case DNSc_STATE_RX_RESP_IPv4:
            case DNSc_STATE_TX_REQ_IPv6:
            case DNSc_STATE_RX_RESP_IPv6:
                 break;

            case DNSc_STATE_FREE:
            case DNSc_STATE_RESOLVED:
            case DNSc_STATE_FAILED:
            default:
                 DNScCache_ItemRelease(p_cache);
                 break;
        }

        p_cache = p_cache_next;
    }

   *p_err = DNSc_ERR_NONE;

    DNScCache_LockRelease();


exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNScCache_HostInsert()
*
* Description : Add an entry in the cache.
*
* Argument(s) : p_host  Pointer to host object.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE   Host successfully inserted.
*
*                           RETURNED BY DNScCache_LockAcquire():
*                               See DNScCache_LockAcquire() for additional return error codes.
*
*                           RETURNED BY DNScCache_ItemGet():
*                               See DNScCache_ItemGet() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : DNScTask_ResolveHost().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_HostInsert (DNSc_HOST_OBJ  *p_host,
                            DNSc_ERR       *p_err)
{
    DNSc_CACHE_ITEM  *p_cache;


    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }

    p_cache = DNScCache_ItemGet(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit_release;
    }

    p_cache->HostPtr = p_host;

    if (DNSc_CacheItemListHead == DEF_NULL) {
        p_cache->NextPtr        = DEF_NULL;
        DNSc_CacheItemListHead  = p_cache;
    } else {
        p_cache->NextPtr        = DNSc_CacheItemListHead;
        DNSc_CacheItemListHead  = p_cache;
    }

   *p_err = DNSc_ERR_NONE;

exit_release:
    DNScCache_LockRelease();

exit:
    return;
}



/*
*********************************************************************************************************
*                                      DNScCache_HostSrchRemove()
*
* Description : Search host name in cache and remove it.
*
* Argument(s) : p_host_name     Pointer to a string that contains the host name.
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE                   Host removed
*                                   DNSc_ERR_CACHE_HOST_NOT_FOUND   Host not found in the cache.
*
*                                   RETURNED BY DNScCache_LockAcquire():
*                                       See DNScCache_LockAcquire() for additional return error codes.
*
*                                   RETURNED BY DNScCache_HostSrchByName():
*                                       See DNScCache_HostSrchByName() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : DNSc_CacheClrHost(),
*               DNSc_GetHost().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_HostSrchRemove (const  CPU_CHAR  *p_host_name,
                                       DNSc_ERR  *p_err)
{
    DNSc_HOST_OBJ  *p_host;


    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }


    p_host = DNScCache_HostSrchByName(p_host_name, DNSc_FLAG_NONE);
    if (p_host != DEF_NULL) {
        switch(p_host->State) {
            case DNSc_STATE_TX_REQ_IPv4:
            case DNSc_STATE_RX_RESP_IPv4:
            case DNSc_STATE_TX_REQ_IPv6:
            case DNSc_STATE_RX_RESP_IPv6:
            case DNSc_STATE_TX_REQ_PTR_IPv4:
            case DNSc_STATE_RX_RESP_PTR_IPv4:
            case DNSc_STATE_TX_REQ_PTR_IPv6:
            case DNSc_STATE_RX_RESP_PTR_IPv6:
                *p_err = DNSc_ERR_CACHE_HOST_PENDING;
                 goto exit_release;

            case DNSc_STATE_RESOLVED:
            case DNSc_STATE_FAILED:
            default:
                *p_err = DNSc_ERR_NONE;
                 DNScCache_HostRemoveHandler(p_host);
                 goto exit_release;
        }
    }

   *p_err  = DNSc_ERR_CACHE_HOST_NOT_FOUND;                     /* Not found.                                           */

    goto exit_release;


exit_release:
    DNScCache_LockRelease();

exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNScCache_HostRemove()
*
* Description : Remove host from the cache.
*
* Argument(s) : p_host  Pointer to the host object.
*
* Return(s)   : None.
*
* Caller(s)   : DNScTask_HostResolve().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_HostRemove (DNSc_HOST_OBJ  *p_host)
{
    DNSc_ERR  err;

    DNScCache_LockAcquire(&err);
    if (err != DNSc_ERR_NONE) {
         goto exit;
    }

    DNScCache_HostRemoveHandler(p_host);

    DNScCache_LockRelease();

exit:
    return;
}


/*
*********************************************************************************************************
*                                           DNScCache_Srch()
*
* Description : Search host in cache and return IP addresses, if found.
*
* Argument(s) : p_host_name         Pointer to a string that contains the host name.
*
*               p_host_obj          Pointer to a pointer to the host entry in the cache (if found).
*
*               p_addrs             Pointer to addresses array.
*
*               addr_nbr_max        Number of address the address array can contain.
*
*               p_addr_nbr_rtn      Pointer to a variable that will receive number of addresses copied.
*
*               flags           DNS client flag:
*
*                                   DNSc_FLAG_NONE              By default all IP address can be returned.
*                                   DNSc_FLAG_IPv4_ONLY         Return only IPv4 address(es).
*                                   DNSc_FLAG_IPv6_ONLY         Return only IPv6 address(es).
*
*               p_err               Pointer to variable that will receive the return error code from this function :
*
*                                       DNSc_ERR_NONE                   Host found.
*                                       DNSc_ERR_CACHE_HOST_PENDING     Host resolution is pending.
*                                       DNSc_ERR_CACHE_HOST_NOT_FOUND   Host not found in the cache.
*
*                                       RETURNED BY DNScCache_LockAcquire():
*                                           See DNScCache_LockAcquire() for additional return error codes.
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
* Note(s)     : (1) 'p_host_obj' is dereferenced & assigned a value of DEF_NULL if cache entry is NOT found.
*********************************************************************************************************
*/

DNSc_STATUS  DNScCache_Srch (const  CPU_CHAR        *p_host_name,
                                    DNSc_HOST_OBJ  **p_host_obj,
                                    DNSc_ADDR_OBJ   *p_addrs,
                                    CPU_INT08U       addr_nbr_max,
                                    CPU_INT08U      *p_addr_nbr_rtn,
                                    DNSc_FLAGS       flags,
                                    DNSc_ERR        *p_err)
{
    CPU_INT08U       i          = 0u;
    DNSc_HOST_OBJ   *p_host     = DEF_NULL;
    DNSc_ADDR_OBJ   *p_addr     = DEF_NULL;
    DNSc_ADDR_ITEM  *p_item     = DEF_NULL;
    DNSc_STATUS      status     = DNSc_STATUS_FAILED;
    CPU_BOOLEAN      no_ipv4    = DEF_BIT_IS_SET(flags, DNSc_FLAG_IPv6_ONLY);
    CPU_BOOLEAN      no_ipv6    = DEF_BIT_IS_SET(flags, DNSc_FLAG_IPv4_ONLY);


   *p_addr_nbr_rtn = 0u;

    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }

    p_host = DNScCache_HostSrchByName(p_host_name, flags);
    if (p_host != DEF_NULL) {
        switch(p_host->State) {
#ifdef  DNSc_TASK_MODULE_EN
            case DNSc_STATE_IF_SEL:                             /* A req for host may have been started by another task.*/
            case DNSc_STATE_INIT_REQ:
#endif
            case DNSc_STATE_TX_REQ_IPv4:
            case DNSc_STATE_RX_RESP_IPv4:
            case DNSc_STATE_TX_REQ_IPv6:
            case DNSc_STATE_RX_RESP_IPv6:
            case DNSc_STATE_TX_REQ_PTR_IPv4:
            case DNSc_STATE_RX_RESP_PTR_IPv4:
            case DNSc_STATE_TX_REQ_PTR_IPv6:
            case DNSc_STATE_RX_RESP_PTR_IPv6:
                 status = DNSc_STATUS_PENDING;
                *p_err  = DNSc_ERR_CACHE_HOST_PENDING;
                 goto exit_release;

            case DNSc_STATE_RESOLVED:
                 status = DNSc_STATUS_RESOLVED;
                 goto exit_found;

            case DNSc_STATE_FAILED:
            default:
                *p_err = DNSc_ERR_NONE;
                 goto exit_release;
        }
    }

   *p_err = DNSc_ERR_CACHE_HOST_NOT_FOUND;                      /* Not found.                                           */

    goto exit_release;


exit_found:

    p_item = p_host->AddrsFirstPtr;


    for (i = 0u; i < p_host->AddrsCount; i++) {                 /* Copy Addresses                                       */
        p_addr = p_item->AddrPtr;
        if (*p_addr_nbr_rtn < addr_nbr_max) {
            CPU_BOOLEAN  add_addr = DEF_YES;


            switch (p_addr->Len) {
                case NET_IPv4_ADDR_SIZE:
                     if (no_ipv4 == DEF_YES) {
                         add_addr = DEF_NO;
                     }
                     break;

                case NET_IPv6_ADDR_SIZE:
                     if (no_ipv6 == DEF_YES) {
                         add_addr = DEF_NO;
                     }
                     break;

                default:
                     add_addr = DEF_NO;
                     break;
            }

            if (add_addr == DEF_YES) {
                p_addrs[*p_addr_nbr_rtn] = *p_addr;
               *p_addr_nbr_rtn += 1u;
            }

            p_item = p_item->NextPtr;

        } else {
            goto exit_release;
        }
    }

   (void)&p_addr_nbr_rtn;

   *p_err = DNSc_ERR_NONE;

exit_release:
    DNScCache_LockRelease();

exit:
   *p_host_obj = p_host;
    return (status);
}


/*
*********************************************************************************************************
*                                        DNScCache_HostObjGet()
*
* Description : Get a free host object.
*
* Argument(s) : p_host_name     Pointer to a string that contains the domain name.
*
*               flags           DNS client flag:
*
*                                   DNSc_FLAG_NONE              By default this function is blocking.
*                                   DNSc_FLAG_NO_BLOCK          Don't block (only possible if DNSc's task is enabled).
*                                   DNSc_FLAG_FORCE_CACHE       Take host from the cache, don't send new DNS request.
*                                   DNSc_FLAG_FORCE_RENEW       Force DNS request, remove existing entry in the cache.
*                                   DNSc_FLAG_CANON             Force this function to allocate a canonical name object.
*                                   DNSc_FLAG_REVERSE_LOOKUP    Force this function to allocate a reverse name object.
*
*               p_cfg           Pointer to a request configuration. Should be set to overwrite default DNS configuration
*                               (such as DNS server, request timeout, etc.). Must be set to DEF_NULL to use default
*                               configuration.
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE           Successfully acquired a host object.
*                                   DNSc_ERR_MEM_ALLOC      Not able to allocate a host object.
*
*                                   RETURNED BY DNScCache_LockAcquire():
*                                       See DNScCache_LockAcquire() for additional return error codes.
*
*                                   RETURNED BY DNScCache_HostObjNameSet():
*                                       See DNScCache_HostObjNameSet() for additional return error codes.
*
* Return(s)   : Pointer to the host object acquired.
*
* Caller(s)   : DNSc_GetHost().
*
* Note(s)     : None.
*********************************************************************************************************
*/

DNSc_HOST_OBJ  *DNScCache_HostObjGet (const  CPU_CHAR      *p_host_name,
                                             DNSc_FLAGS     flags,
                                             DNSc_REQ_CFG  *p_cfg,
                                             DNSc_ERR      *p_err)
{
#ifdef DNSc_SIGNAL_TASK_MODULE_EN
    KAL_SEM_HANDLE   sem    = KAL_SemHandleNull;
#endif
    DNSc_HOST_OBJ   *p_host = DEF_NULL;
    LIB_ERR          err;


    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }

    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_RESET_REQ)) {
        p_host = DNScCache_HostSrchByName(p_host_name, flags);
        if (p_host != DEF_NULL) {
            goto host_assign_req_params;
        }
    }

    p_host = (DNSc_HOST_OBJ *)Mem_DynPoolBlkGet(&DNScCache_HostObjPool, &err);
    if (err == LIB_MEM_ERR_NONE) {
        p_host->NamePtr = (CPU_CHAR *)Mem_DynPoolBlkGet(&DNScCache_HostNamePool, &err);
        if (err != LIB_MEM_ERR_NONE) {
           *p_err = DNSc_ERR_MEM_ALLOC;
            goto exit_free_host_obj;
        }
    } else {
        p_host = DNScCache_ItemHostGet();
    }

    if (p_host == DEF_NULL) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit_release;
    }
                                                                /* ---------- ACQUIRE SIGNAL TASK SEMAPHORE ----------- */


    if (p_host->NamePtr == DEF_NULL) {
        p_host->NameLenMax = DNScCache_HostNamePool.BlkSize - 1;
    }

    p_host->NameLenMax = DNScCache_HostNamePool.BlkSize;
    Mem_Clr(p_host->NamePtr, p_host->NameLenMax);

    if (p_host->CanonicalNamePtr == DEF_NULL) {
        if (DEF_BIT_IS_SET(flags, DNSc_FLAG_CANON) == DEF_YES) {
            p_host->CanonicalNamePtr = (CPU_CHAR *)Mem_DynPoolBlkGet(&DNScCache_HostCanonNamePool, &err);
            if (err != LIB_MEM_ERR_NONE) {
               *p_err = DNSc_ERR_MEM_ALLOC;
                goto exit_free_host_obj;
            }
            Mem_Clr(p_host->CanonicalNamePtr, p_host->NameLenMax);
        }
    }

    p_host->AddrsCount     = 0u;
    p_host->AddrsIPv4Count = 0u;
    p_host->AddrsIPv6Count = 0u;
    p_host->QueryID        = DNSc_QUERY_ID_NONE;
    p_host->ReqCtr         = 0u;
    p_host->AddrsFirstPtr  = DEF_NULL;
    p_host->AddrsEndPtr    = DEF_NULL;
    p_host->State          = DNSc_STATE_INIT_REQ;

    DNScCache_HostObjNameSet(p_host, p_host_name, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit_release;
    }

host_assign_req_params:
#ifdef DNSc_SIGNAL_TASK_MODULE_EN
    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_NO_BLOCK) == DEF_NO) {
        KAL_ERR  kal_err;


        if (p_host->TaskSignal.SemObjPtr == KAL_SemHandleNull.SemObjPtr) {
            sem = KAL_SemCreate("DNSc Block Task Signal", DEF_NULL, &kal_err);
            if (kal_err != KAL_ERR_NONE) {
               *p_err = DNSc_ERR_MEM_ALLOC;
                goto exit_free_host_obj;
            }
        }
        p_host->TaskSignal = sem;
    }
#endif

    if (p_host->ReverseNamePtr == DEF_NULL) {
        if (DEF_BIT_IS_SET(flags, DNSc_FLAG_REVERSE_LOOKUP) == DEF_YES) {
            p_host->ReverseNamePtr = (CPU_CHAR *)Mem_DynPoolBlkGet(&DNScCache_HostRevNamePool, &err);
            if (err != LIB_MEM_ERR_NONE) {
               *p_err = DNSc_ERR_MEM_ALLOC;
                goto exit_free_host_obj;
            }
            Mem_Clr(p_host->ReverseNamePtr, p_host->NameLenMax);
        }
    }


    if (p_host->ReqCfgPtr == DEF_NULL) {
        p_host->ReqCfgPtr = (DNSc_REQ_CFG *)Mem_DynPoolBlkGet(&DNScCache_ReqCfgPool, &err);
        if (err != LIB_MEM_ERR_NONE) {
           *p_err  = DNSc_ERR_MEM_ALLOC;
            goto exit_free_host_obj;
        }
    }

    p_host->ReqCfgPtr->ReqFlags      = p_cfg->ReqFlags;
    p_host->ReqCfgPtr->ReqRetry      = p_cfg->ReqRetry;
    p_host->ReqCfgPtr->ReqTimeout_ms = p_cfg->ReqTimeout_ms;
    p_host->ReqCfgPtr->ReqType       = p_cfg->ReqType;
    p_host->ReqCfgPtr->ServerAddrPtr = p_cfg->ServerAddrPtr;
    p_host->ReqCfgPtr->ServerPort    = p_cfg->ServerPort;
    p_host->ReqCfgPtr->TaskDly_ms    = p_cfg->TaskDly_ms;


    p_host->TS_ms  = 0u;
    p_host->IF_Nbr = NET_IF_NBR_WILDCARD;
    p_host->SockID = NET_SOCK_ID_NONE;

    if ((DEF_BIT_IS_SET(flags, DNSc_FLAG_RESET_REQ) && (p_host->State == DNSc_STATE_RESOLVED))) {
        p_host->State = DNSc_STATE_INIT_REQ;
    }

    goto exit_release;


exit_free_host_obj:
    Mem_DynPoolBlkFree(&DNScCache_HostObjPool, p_host, &err);

exit_release:
    DNScCache_LockRelease();

exit:
    return (p_host);
}


/*
*********************************************************************************************************
*                                        DNScCache_HostObjFree()
*
* Description : Free a host object.
*
* Argument(s) : p_host  Pointer to the host object to free.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_HostRelease(),
*               DNSc_GetHost().
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_HostObjFree (DNSc_HOST_OBJ  *p_host)
{
    LIB_ERR  err;


#ifdef DNSc_SIGNAL_TASK_MODULE_EN
    if (p_host->TaskSignal.SemObjPtr != KAL_SemHandleNull.SemObjPtr) {
        KAL_ERR  kal_err;


        KAL_SemDel(p_host->TaskSignal, &kal_err);
    }

    p_host->TaskSignal = KAL_SemHandleNull;
#endif


    DNScCache_HostAddrClr(p_host);
    Mem_DynPoolBlkFree(&DNScCache_HostNamePool, p_host->NamePtr, &err);
                                                                /* .CanonicalNamePtr & .ReverseNamePtr were allocated...*/
                                                                /* ...if these features were configured  and if their...*/
                                                                /* ...respective flags were set. If they were not set...*/
                                                                /* ...the following call(s) return(s) an error, which...*/
                                                                /* ...shall be ignored.                                 */
    Mem_DynPoolBlkFree(&DNScCache_HostCanonNamePool, p_host->CanonicalNamePtr, &err);
    Mem_DynPoolBlkFree(&DNScCache_HostRevNamePool,   p_host->ReverseNamePtr,   &err);
    Mem_DynPoolBlkFree(&DNScCache_ReqCfgPool,        p_host->ReqCfgPtr,        &err);
    Mem_DynPoolBlkFree(&DNScCache_HostObjPool,       p_host,                   &err);

    p_host->ReverseNamePtr = (CPU_CHAR *)DEF_NULL;
}


/*
*********************************************************************************************************
*                                      DNScCache_HostAddrInsert()
*
* Description : Insert address object in the addresses list of the host object.
*
* Argument(s) : p_cfg       Pointer to DNSc's configuration.
*
*               p_host      Pointer to the host object.
*
*               p_addr      Pointer to the address object (must be acquired with cache module)
*
*               is_reverse  Indicates if address has been previously resolved as a result of a reverse lookup.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE       Address successfully added.
*                               DNSc_ERR_MEM_ALLOC  Unable to insert the IP address due to the memory configuration
*                               DNSc_ERR_FAULT      Unknown error (should not occur)
*
*                               RETURNED BY DNScCache_AddrItemGet():
*                                   See DNScCache_AddrItemGet() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : DNScReq_RxRespAddAddr().
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_HostAddrInsert (const  DNSc_CFG       *p_cfg,
                                       DNSc_HOST_OBJ  *p_host,
                                       DNSc_ADDR_OBJ  *p_addr,
                                       CPU_BOOLEAN     is_reverse,
                                       DNSc_ERR       *p_err)
{
    DNSc_ADDR_ITEM  *p_item_cur;


    switch (p_addr->Len) {
        case NET_IPv4_ADDR_SIZE:
             if (p_host->AddrsIPv4Count >= p_cfg->AddrIPv4MaxPerHost) {
                *p_err = DNSc_ERR_MEM_ALLOC;
                 return;
             }
             break;


        case NET_IPv6_ADDR_SIZE:
             if (p_host->AddrsIPv6Count >= p_cfg->AddrIPv6MaxPerHost) {
                *p_err = DNSc_ERR_MEM_ALLOC;
                 return;
             }
             break;


        default:
            *p_err = DNSc_ERR_FAULT;
             return;
    }
                                                                /* If reverse DNS lookup, the addr item was already ... */
    if (!is_reverse) {                                          /* ... acquired by DNScCache_Resolve().                 */
        p_item_cur = DNScCache_AddrItemGet(p_err);
        if (*p_err != DNSc_ERR_NONE) {
             return;
        }
        p_item_cur->AddrPtr = p_addr;

        if (p_host->AddrsFirstPtr == DEF_NULL) {
            p_host->AddrsFirstPtr             = p_item_cur;
            p_host->AddrsEndPtr               = p_item_cur;

        } else {
            p_host->AddrsEndPtr->NextPtr = p_item_cur;
            p_host->AddrsEndPtr          = p_item_cur;
        }
    }

    switch (p_addr->Len) {
        case NET_IPv4_ADDR_SIZE:
             p_host->AddrsIPv4Count++;
             break;


        case NET_IPv6_ADDR_SIZE:
             p_host->AddrsIPv6Count++;
             break;

        default:
            *p_err = DNSc_ERR_FAULT;
             return;
    }

    p_host->AddrsCount++;

   *p_err = DNSc_ERR_NONE;

    return;
}


/*
*********************************************************************************************************
*                                        DNScCache_AddrObjGet()
*
* Description : Acquire an address object that can be inserted in host list afterward.
*
* Argument(s) : p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE   Successfully acquired an address object.
*                           DNSc_ERR_MEM_ALLOC  Unable to acquire an address object.
*
* Return(s)   : Pointer to the address object acquired, if no error.
*
*               DEF_NULL, otherwise
*
* Caller(s)   : DNScReq_RxRespAddAddr().
*
* Note(s)     : None.
*********************************************************************************************************
*/

DNSc_ADDR_OBJ  *DNScCache_AddrObjGet (DNSc_ERR  *p_err)
{
    DNSc_ADDR_OBJ  *p_addr = DEF_NULL;
    LIB_ERR         err;


    p_addr = (DNSc_ADDR_OBJ *)Mem_DynPoolBlkGet(&DNScCache_AddrObjPool, &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    Mem_Clr(p_addr, sizeof(DNSc_ADDR_OBJ));

   *p_err = DNSc_ERR_NONE;

exit:
    return (p_addr);
}


/*
*********************************************************************************************************
*                                        DNScCache_AddrObjFree()
*
* Description : Free an address object
*
* Argument(s) : p_addr  Pointer to address object to free.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_AddrItemFree(),
*               DNScReq_RxRespAddAddr().
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_AddrObjFree (DNSc_ADDR_OBJ  *p_addr)
{
    LIB_ERR  err;


    Mem_DynPoolBlkFree(&DNScCache_AddrObjPool, p_addr, &err);
   (void)&err;
}


/*
*********************************************************************************************************
*                                        DNScCache_AddrObjSet()
*
* Description : Set address object from IP string.
*
* Argument(s) : p_addr      Pointer to the address object.
*
*               p_str_addr  Pointer to the string that contains the IP address.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE           Address successfully set.
*                               DNSc_ERR_ADDR_INVALID   Invalid IP address.
*
* Return(s)   : None.
*
* Caller(s)   : DNScReq_ServerInit(),
*               DNSc_CfgServerByStr().
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCache_AddrObjSet (DNSc_ADDR_OBJ  *p_addr,
                            CPU_CHAR       *p_str_addr,
                            DNSc_ERR       *p_err)
{
    NET_IP_ADDR_FAMILY  ip_addr_family;
    NET_ERR             net_err;


    ip_addr_family = NetASCII_Str_to_IP(         p_str_addr,
                                        (void *)&p_addr->Addr,
                                                 sizeof(p_addr->Addr),
                                                &net_err);
    if (net_err != NET_ASCII_ERR_NONE) {
        *p_err = DNSc_ERR_ADDR_INVALID;
         goto exit;
    }

    switch (ip_addr_family) {
        case NET_IP_ADDR_FAMILY_IPv4:
             p_addr->Len = NET_IPv4_ADDR_SIZE;
             break;

        case NET_IP_ADDR_FAMILY_IPv6:
             p_addr->Len = NET_IPv6_ADDR_SIZE;
             break;

        default:
            *p_err = DNSc_ERR_ADDR_INVALID;
             goto exit;
    }

   *p_err = DNSc_ERR_NONE;

    exit:
        return;
}


/*
*********************************************************************************************************
*                                        DNScCache_ResolveHost()
*
* Description : Launch resolution of an host.
*
* Argument(s) : p_cfg   Pointer to DNSc's configuration.
*
*               p_host  Pointer to the host object.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           RETURNED BY DNScCache_LockAcquire():
*                               See DNScCache_LockAcquire() for additional return error codes.
*
*                           RETURNED BY DNScCache_Resolve():
*                               See DNScCache_Resolve() for additional return error codes.
*
* Return(s)   : Resolution status:
*                       DNSc_STATUS_PENDING         Host resolution is pending, call again to see the status. (Processed by DNSc's task)
*                       DNSc_STATUS_RESOLVED        Host is resolved.
*                       DNSc_STATUS_FAILED          Host resolution has failed.
*
* Caller(s)   : DNScTask().
*
* Note(s)     : None.
*********************************************************************************************************
*/

DNSc_STATUS  DNScCache_ResolveHost (const  DNSc_CFG       *p_cfg,
                                           DNSc_HOST_OBJ  *p_host,
                                           DNSc_ERR       *p_err)
{
    DNSc_STATUS  status;


    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }


    status = DNScCache_Resolve(p_cfg, p_host, p_err);

    DNScCache_LockRelease();


exit:
    return (status);
}


/*
*********************************************************************************************************
*                                        DNScCache_ResolveAll()
*
* Description : Launch resolution on all entries that are pending in the cache.
*
* Argument(s) : p_cfg   Pointer to DNSc's configuration.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE   Resolution has been launched on all entries.
*
*                           RETURNED BY DNScCache_LockAcquire():
*                               See DNScCache_LockAcquire() for additional return error codes.
*
* Return(s)   : Number of entries that are completed.
*
* Caller(s)   : DNScTask().
*
* Note(s)     : None.
*********************************************************************************************************
*/

CPU_INT16U  DNScCache_ResolveAll (const  DNSc_CFG  *p_cfg,
                                         DNSc_ERR  *p_err)
{
    DNSc_CACHE_ITEM  *p_item;
    DNSc_HOST_OBJ    *p_host;
    DNSc_STATUS       status;
    CPU_INT16U        resolved_ctr = 0u;


    DNScCache_LockAcquire(p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }


    p_item = DNSc_CacheItemListHead;

    while (p_item != DEF_NULL) {
        p_host = p_item->HostPtr;

        if (p_host->State != DNSc_STATE_RESOLVED) {
            status = DNScCache_Resolve(p_cfg, p_host, p_err);
            switch (status) {
                case DNSc_STATUS_NONE:
                case DNSc_STATUS_PENDING:
                     break;

                case DNSc_STATUS_RESOLVED:
                case DNSc_STATUS_FAILED:
                default:
#ifdef  DNSc_SIGNAL_TASK_MODULE_EN
                    if (KAL_SEM_HANDLE_IS_NULL(p_host->TaskSignal) != DEF_YES) {
                        KAL_ERR  kal_err;


                        KAL_SemPost(p_host->TaskSignal, KAL_OPT_NONE, &kal_err);
                    }
#endif
                    resolved_ctr++;
                    break;
            }
        }

        p_item = p_item->NextPtr;
    }


   *p_err = DNSc_ERR_NONE;

    DNScCache_LockRelease();


exit:
    return (resolved_ctr);
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
*                                        DNScCache_LockAcquire()
*
* Description : Acquire lock on the cache list.
*
* Argument(s) : p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Lock successfully acquired.
*                           DNSc_ERR_CACHE_LOCK     Unable to acquire the lock.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_Clr(),
*               DNScCache_HostInsert(),
*               DNScCache_HostObjGet(),
*               DNScCache_HostRemove(),
*               DNScCache_HostSrchRemove(),
*               DNScCache_ResolveAll(),
*               DNScCache_ResolveHost(),
*               DNScCache_Srch().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_LockAcquire (DNSc_ERR  *p_err)
{
    KAL_ERR  err;


    KAL_LockAcquire(DNScCache_LockHandle, KAL_OPT_PEND_NONE, 0, &err);
    if (err != KAL_ERR_NONE) {
        *p_err = DNSc_ERR_CACHE_LOCK;
         goto exit;
    }


   *p_err = DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNScCache_LockRelease()
*
* Description : Release cache list lock.
*
* Argument(s) : None.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_Clr(),
*               DNScCache_HostInsert(),
*               DNScCache_HostObjGet(),
*               DNScCache_HostRemove(),
*               DNScCache_HostSrchRemove(),
*               DNScCache_ResolveAll(),
*               DNScCache_ResolveHost(),
*               DNScCache_Srch().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_LockRelease (void)
{
    KAL_ERR  err;


    KAL_LockRelease(DNScCache_LockHandle, &err);
}


/*
*********************************************************************************************************
*                                     DNScCache_HostRemoveHandler()
*
* Description : Remove host from the cache.
*
* Argument(s) : p_host  Pointer to the host object.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_HostRemove(),
*               DNScCache_HostSrchRemove().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_HostRemoveHandler (DNSc_HOST_OBJ  *p_host)
{
    DNSc_CACHE_ITEM  *p_cache = DNSc_CacheItemListHead;


    while (p_cache != DEF_NULL) {
        if (p_cache->HostPtr == p_host) {
            DNScCache_ItemRelease(p_cache);
            goto exit;
        }
        p_cache = p_cache->NextPtr;
    }

exit:
    return;
}


/*
*********************************************************************************************************
*                                      DNScCache_HostObjNameSet()
*
* Description : Set the name in host object.
*
* Argument(s) : p_host          Pointer to the host object to set.
*
*               p_host_name     Pointer to a string that contains the domain name.

*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE   Host name successfully set.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_HostObjGet().
*               DNScCache_Resolve().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_HostObjNameSet (       DNSc_HOST_OBJ  *p_host,
                                        const  CPU_CHAR       *p_host_name,
                                               DNSc_ERR       *p_err)
{
     Str_Copy_N(p_host->NamePtr, p_host_name, p_host->NameLenMax);
    *p_err = DNSc_ERR_NONE;
}


/*
*********************************************************************************************************
*                                      DNScCache_HostSrchByName()
*
* Description : Search for an host in the cache from a host name string.
*
* Argument(s) : p_host_name     Pointer to a string that contains the domain name.
*
*               flags           Flags that determine DNS options. Used to determine reverse lookup.
*
* Return(s)   : Pointer to the host object, if found.
*
*               DEF_NULL, Otherwise.
*
* Caller(s)   : DNScCache_HostSrchRemove(),
*               DNScCache_Srch().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  DNSc_HOST_OBJ  *DNScCache_HostSrchByName (const  CPU_CHAR    *p_host_name,
                                                         DNSc_FLAGS   flags)
{
    DNSc_HOST_OBJ    *p_host  = DEF_NULL;
    DNSc_CACHE_ITEM  *p_cache = DNSc_CacheItemListHead;
    CPU_BOOLEAN       match;


    if (p_cache == DEF_NULL) {
        goto exit;
    }

    while (p_cache != DEF_NULL) {
        p_host = p_cache->HostPtr;
        match  = DNScCache_HostNameCmp(p_host, p_host_name, flags);
        if (match == DEF_YES) {
            goto exit;
        }

        p_cache = p_cache->NextPtr;
    }

    p_host = DEF_NULL;

exit:
    return (p_host);
}


/*
*********************************************************************************************************
*                                        DNScCache_HostNameCmp()
*
* Description : Compare host object name field to a host name string.
*
* Argument(s) : p_host       Pointer to the host object.
*
*               p_host_name  Pointer to a string that contains the host name.
*
*               flags        Flags that determine DNS options. Used to determine reverse lookup.
*
* Return(s)   : DEF_OK, if names match
*
*               DEF_FAIL, otherwise
*
* Caller(s)   : DNScCache_HostSrchByName().
*
* Note(s)     : (1). The host structure's .NamePtr field in a reverse DNS request may have either a
*                    domain name or a dotted string representation of the IP address. This is because
*                    the host may have been resolved by a previous forward DNS request. For this reason
*                    we compare 'p_host' with .NamePtr if the latter's NetASCII conversion succeeds, and
*                    to the resolved IP address if the conversion fails. Please note that this algorithm
*                    does not apply to the converse. That is, if the host was previously resolved by a
*                    reverse DNS lookup and if a forward lookup is issued for the same host, this function
*                    will not match the reverse name to the domain name being searched in p_host_name.
*********************************************************************************************************
*/

static  CPU_BOOLEAN  DNScCache_HostNameCmp (       DNSc_HOST_OBJ  *p_host,
                                            const  CPU_CHAR       *p_host_name,
                                                   DNSc_FLAGS      flags)
{
    CPU_INT16S       cmp;
    CPU_BOOLEAN      result           = DEF_FAIL;
    CPU_BOOLEAN      addr_found       = DEF_NO;
#ifdef  NET_IPv4_MODULE_EN
    CPU_CHAR        *p_host_name_srch = "";
    CPU_CHAR         host_name_from_addr[DNSc_ADDR_SIZE];
    NET_IPv4_ADDR    addr;
#endif
#ifdef  NET_IPv6_MODULE_EN
    NET_IPv6_ADDR    addr_ipv6;
#endif
    CPU_INT08U       addr_len;
    DNSc_ADDR_ITEM  *p_resolved_addr;
    CPU_BOOLEAN      is_reverse       = DEF_BIT_IS_SET(flags, DNSc_FLAG_REVERSE_LOOKUP);
    NET_ERR          net_err          = NET_ASCII_ERR_INVALID_CHAR_VAL;


    if (!is_reverse) {
                                                                /* Compare host name with .NamePtr for forward requests.*/
        cmp = Str_Cmp_N(p_host_name, p_host->NamePtr, p_host->NameLenMax);
        if (cmp == 0) {
            result = DEF_OK;
        }
    } else {
        p_resolved_addr = p_host->AddrsFirstPtr;

        while (p_resolved_addr != DEF_NULL) {                   /* Loop through resolved addrs & select preferred addr. */
            addr_len = p_resolved_addr->AddrPtr->Len;
            if (DEF_BIT_IS_SET(flags, DNSc_FLAG_UPDATE_PREF)) { /* Update preferred address if required.                */
                p_resolved_addr->AddrPtr->RevPreferred = DEF_NO;
            }

#ifdef  NET_IPv4_MODULE_EN
            if ((addr_found == DEF_NO) && (addr_len == NET_IPv4_ADDR_LEN)) {
                Mem_Copy(&addr, (p_resolved_addr->AddrPtr->Addr), addr_len);

                NetASCII_IPv4_to_Str( addr,
                                      host_name_from_addr,
                                      DEF_NO,
                                     &net_err);

               (void)NetASCII_Str_to_IP( p_host->NamePtr,       /* Check if NamePtr is string representation of IP addr.*/
                                        &addr,
                                         DNSc_ADDR_SIZE,
                                        &net_err);
                                                                /* If it is, use it for comparison.                     */
                                                                /* Otherwise use previously resolved IP. (See Note #1). */
                p_host_name_srch = (net_err == NET_ASCII_ERR_NONE) ?
                                    p_host->NamePtr                :
                                    host_name_from_addr;
                                                                /* Compare host names for reverse IPv4 requests.        */

                cmp = Str_Cmp_N(p_host_name, p_host_name_srch, p_host->NameLenMax);
                result      = (cmp == 0u);
                addr_found |= result;

                if (DEF_BIT_IS_SET(flags, DNSc_FLAG_UPDATE_PREF)) { /* Update preferred address if required.            */
                    p_resolved_addr->AddrPtr->RevPreferred = addr_found;
                }
            }
#endif
#ifdef  NET_IPv6_MODULE_EN
            if ((addr_found == DEF_NO)             &&
                (addr_len   == NET_IPv6_ADDR_LEN)) {            /* Check if NamePtr is string representation of IP addr.*/
                addr_ipv6 = NetASCII_Str_to_IPv6((CPU_CHAR *)p_host_name,
                                                            &net_err);

                if (net_err == NET_ASCII_ERR_NONE) {
                    addr_found = Mem_Cmp(addr_ipv6.Addr, p_resolved_addr->AddrPtr->Addr, NET_IPv6_ADDR_LEN);
                    result    |= addr_found;

                    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_UPDATE_PREF)) { /* Update preferred address if required.        */
                        p_resolved_addr->AddrPtr->RevPreferred = addr_found;
                    }
                }
            }
#endif
            p_resolved_addr = p_resolved_addr->NextPtr;
        }
    }

    return (result);
}


/*
*********************************************************************************************************
*                                          DNScCache_ItemGet()
*
* Description : Get an Cache item element (list element)
*
* Argument(s) : p_err   Pointer to variable that will receive the return error code from this function :
*
* Return(s)   : Pointer to the item element.
*
* Caller(s)   : DNScCache_HostInsert().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  DNSc_CACHE_ITEM  *DNScCache_ItemGet (DNSc_ERR  *p_err)
{
    DNSc_CACHE_ITEM  *p_cache;
    LIB_ERR           err;


    p_cache = (DNSc_CACHE_ITEM *)Mem_DynPoolBlkGet(&DNScCache_ItemPool, &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

   *p_err = DNSc_ERR_NONE;

exit:
    return (p_cache);
}


/*
*********************************************************************************************************
*                                         DNScCache_ItemFree()
*
* Description : Free cache item element.
*
* Argument(s) : p_cache Pointer to cache item element.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_ItemHostGet(),
*               DNScCache_ItemRelease().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_ItemFree (DNSc_CACHE_ITEM  *p_cache)
{
    LIB_ERR  err;


    Mem_DynPoolBlkFree(&DNScCache_ItemPool, p_cache, &err);
}



/*
*********************************************************************************************************
*                                        DNScCache_ItemHostGet()
*
* Description : Get host item element (list element).
*
* Argument(s) : none.
*
* Return(s)   : Pointer to host item element.
*
* Caller(s)   : DNScCache_HostObjGet().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  DNSc_HOST_OBJ  *DNScCache_ItemHostGet (void)
{
    DNSc_CACHE_ITEM  *p_item_cur = DNSc_CacheItemListHead;
    DNSc_HOST_OBJ    *p_host     = DEF_NULL;


    if (p_item_cur == DEF_NULL) {
        goto exit;
    }


    while (p_item_cur != DEF_NULL) {
        p_host = p_item_cur->HostPtr;
        switch (p_host->State) {
            case DNSc_STATE_TX_REQ_IPv4:
            case DNSc_STATE_RX_RESP_IPv4:
            case DNSc_STATE_TX_REQ_IPv6:
            case DNSc_STATE_RX_RESP_IPv6:
            case DNSc_STATE_TX_REQ_PTR_IPv4:
            case DNSc_STATE_RX_RESP_PTR_IPv4:
            case DNSc_STATE_TX_REQ_PTR_IPv6:
            case DNSc_STATE_RX_RESP_PTR_IPv6:
                 break;

            case DNSc_STATE_FREE:
            case DNSc_STATE_FAILED:
            case DNSc_STATE_RESOLVED:
                 goto exit_found;

            default:
                 p_host = DEF_NULL;
                 goto exit;
        }
        p_item_cur = p_item_cur->NextPtr;
    }


    p_host = DEF_NULL;
    goto exit;


exit_found:
    DNScCache_ItemRemove(p_item_cur);
    DNScCache_HostAddrClr(p_host);

exit:
    return (p_host);
}


/*
*********************************************************************************************************
*                                        DNScCache_ItemRelease()
*
* Description : Release a cache item and everything contained in the item.
*
* Argument(s) : p_cache     Pointer to the cache item.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_Clr(),
*               DNScCache_HostRemoveHandler().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_ItemRelease (DNSc_CACHE_ITEM  *p_cache)
{
    if (p_cache->HostPtr != DEF_NULL) {
        DNScCache_HostRelease(p_cache->HostPtr);
    }

    DNScCache_ItemRemove(p_cache);
}


/*
*********************************************************************************************************
*                                        DNScCache_ItemRemove()
*
* Description : Remove an item (list element) in the cache.
*
* Argument(s) : p_cache     Pointer to the cache list element to remove.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_ItemHostGet(),
*               DNScCache_ItemRelease().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_ItemRemove (DNSc_CACHE_ITEM  *p_cache)
{
    if (DNSc_CacheItemListHead == p_cache) {
        DNSc_CacheItemListHead = p_cache->NextPtr;
        goto exit_found;

    } else {
        DNSc_CACHE_ITEM  *p_cache_cur  = DNSc_CacheItemListHead->NextPtr;
        DNSc_CACHE_ITEM  *p_cache_prev = DNSc_CacheItemListHead;

        while (p_cache_cur != DEF_NULL) {
            if (p_cache_cur == p_cache) {
                p_cache_prev->NextPtr = p_cache_cur->NextPtr;
                goto exit_found;
            }
            p_cache_prev = p_cache_cur;
            p_cache_cur  = p_cache_cur->NextPtr;
        }
    }

    goto exit;


exit_found:
    DNScCache_ItemFree(p_cache);

exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNScCache_AddrItemGet()
*
* Description : get an address item element (list)
*
* Argument(s) : p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE       Successfully acquired an address element.
*                           DNSc_ERR_MEM_ALLOC  Unable to acquire an address element.
*
* Return(s)   : Pointer to address element, if no error.
*
*               DEF_NULL, otherwise.
*
* Caller(s)   : DNScCache_HostAddrInsert().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  DNSc_ADDR_ITEM  *DNScCache_AddrItemGet (DNSc_ERR  *p_err)
{
    DNSc_ADDR_ITEM  *p_item = DEF_NULL;
    LIB_ERR          err;


    p_item = (DNSc_ADDR_ITEM *)Mem_DynPoolBlkGet(&DNScCache_AddrItemPool, &err);
    if (err != LIB_MEM_ERR_NONE) {
       *p_err = DNSc_ERR_MEM_ALLOC;
        goto exit;
    }

    p_item->AddrPtr = DEF_NULL;
    p_item->NextPtr = DEF_NULL;

   *p_err = DNSc_ERR_NONE;

exit:
    return (p_item);
}



/*
*********************************************************************************************************
*                                       DNScCache_AddrItemFree()
*
* Description : Free an address item element.
*
* Argument(s) : p_item  Pointer to the address item element.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_HostRelease().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_AddrItemFree (DNSc_ADDR_ITEM  *p_item)
{
    LIB_ERR  err;


    DNScCache_AddrObjFree(p_item->AddrPtr);
    if (p_item->AddrPtr != DEF_NULL) {
        Mem_DynPoolBlkFree(&DNScCache_AddrItemPool, p_item, &err);
    }

   (void)&err;
}

/*
*********************************************************************************************************
*                                        DNScCache_HostRelease()
*
* Description : Release an host and all element contained in the host.
*
* Argument(s) : p_host  Pointer to the host object.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_ItemRelease().
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  void  DNScCache_HostRelease (DNSc_HOST_OBJ  *p_host)
{


    DNScCache_HostAddrClr(p_host);
    DNScCache_HostObjFree(p_host);
}




/*
*********************************************************************************************************
*                                        DNScCache_HostAddrClr()
*
* Description : Remove and free all address elements contained in a host object.
*
* Argument(s) : p_host  Pointer to the host object.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_HostObjFree(),
*               DNScCache_HostRelease(),
*               DNScCache_ItemHostGet().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_HostAddrClr (DNSc_HOST_OBJ  *p_host)
{
    DNSc_ADDR_ITEM  *p_addr_coll_cur  = p_host->AddrsFirstPtr;
    DNSc_ADDR_ITEM  *p_addr_coll_next = DEF_NULL;


    while (p_addr_coll_cur != DEF_NULL) {
        p_addr_coll_next = p_addr_coll_cur->NextPtr;

        DNScCache_AddrItemFree(p_addr_coll_cur);

        p_addr_coll_cur = p_addr_coll_next;
    }

    p_host->AddrsFirstPtr = DEF_NULL;
    p_host->AddrsEndPtr   = DEF_NULL;
}


/*
*********************************************************************************************************
*                                          DNScCache_Resolve()
*
* Description : Process resolution of an host (state machine controller).
*
* Argument(s) : p_cfg   Pointer to DNSc's configuration.
*
*               p_host  Pointer to the host object.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE               No error.
*                           DNSc_ERR_MEM_ALLOC          Not enough resources in addr obj pool to complete reverse lookup.
*                           DNSc_ERR_FAULT              Unknown error (should not occur).
*                           DNSc_ERR_INVALID_HOST_NAME  Host name could not be set in host structure.
*
*                           RETURNED BY DNScReq_Init():
*                               See DNScReq_Init() for additional return error codes.
*
*                           RETURNED BY DNScCache_Req():
*                               See DNScCache_Req() for additional return error codes.
*
*                           RETURNED BY DNScCache_Resp():
*                               See DNScCache_Resp() for additional return error codes.
*
* Return(s)   : Resolution status:
*                       DNSc_STATUS_PENDING         Host resolution is pending, call again to see the status. (Processed by DNSc's task)
*                       DNSc_STATUS_RESOLVED        Host is resolved.
*                       DNSc_STATUS_FAILED          Host resolution has failed.
*
* Caller(s)   : DNScCache_ResolveAll(),
*               DNScCache_ResolveHost().
*
* Note(s)     : none.
*********************************************************************************************************
*/

static  DNSc_STATUS  DNScCache_Resolve (const  DNSc_CFG       *p_cfg,
                                               DNSc_HOST_OBJ  *p_host,
                                               DNSc_ERR       *p_err)
{
    DNSc_STATUS      status              = DNSc_STATUS_PENDING;
    DNSc_ADDR_OBJ   *p_server_addr       = DEF_NULL;
    NET_PORT_NBR     server_port         = NET_PORT_NBR_NONE;
    CPU_BOOLEAN      resolved_addr_found = DEF_NO;
    DNSc_ADDR_OBJ   *p_resolved_addr     = DEF_NULL;
    DNSc_ADDR_OBJ   *p_preferred_addr    = DEF_NULL;
    DNSc_ADDR_ITEM  *p_item;
    DNSc_ADDR_OBJ   *p_addr_obj;
    CPU_CHAR        *p_reverse_name;
    CPU_INT16U       len;
#ifdef  NET_IPv4_MODULE_EN
    NET_IPv4_ADDR    addr;
#endif
#ifdef  NET_IPv6_MODULE_EN
    NET_IPv6_ADDR    addr_ipv6;
#endif
    DNSc_ERR         dnsc_err;
    NET_ERR          net_err;


    switch (p_host->State) {
        case DNSc_STATE_INIT_REQ:
             if (p_host->ReqCfgPtr != DEF_NULL) {
                 p_server_addr = p_host->ReqCfgPtr->ServerAddrPtr;
                 server_port   = p_host->ReqCfgPtr->ServerPort;
             }

             p_host->SockID = DNScReq_Init(p_server_addr, server_port, p_err);
             if (*p_err != DNSc_ERR_NONE) {
                 status = DNSc_STATUS_FAILED;
                 goto exit;
             }

             p_host->ReqCtr = 0u;
             p_host->State  = DNSc_STATE_IF_SEL;
             status         = DNSc_STATUS_PENDING;
             break;


        case DNSc_STATE_IF_SEL:
             p_host->IF_Nbr = DNSc_ReqIF_Sel(p_host->IF_Nbr, p_host->SockID, p_err);
             if (*p_err != DNSc_ERR_NONE) {
                 status = DNSc_STATUS_FAILED;
                 break;
             }

#ifdef  NET_IP_MODULE_EN
    #ifdef  NET_IPv4_MODULE_EN
             if (DEF_BIT_IS_CLR(p_host->ReqCfgPtr->ReqFlags, DNSc_FLAG_REVERSE_LOOKUP)) {
                 p_host->State = DNSc_STATE_TX_REQ_IPv4;
             } else {
                 if (p_host->ReqCfgPtr->ReqType == DNSc_REQ_TYPE_PTR_IPv4) {
                     p_host->State = DNSc_STATE_TX_REQ_PTR_IPv4;
                 }
             }
    #endif
    #ifdef  NET_IPv6_MODULE_EN
             if (DEF_BIT_IS_CLR(p_host->ReqCfgPtr->ReqFlags, DNSc_FLAG_REVERSE_LOOKUP)) {
                 if (p_host->State == DNSc_STATE_IF_SEL) {      /* If prev ReqType was not DNSc_STATE_TX_REQ_IPv4 NOR...*/
                     p_host->State = DNSc_STATE_TX_REQ_IPv6;    /* ...DNSc_STATE_TX_REQ_PTR_IPv4, check if it's IPv6.   */
                 }
             } else {
                 if (p_host->ReqCfgPtr->ReqType == DNSc_REQ_TYPE_PTR_IPv6) {
                     p_host->State = DNSc_STATE_TX_REQ_PTR_IPv6;
                 }
             }
    #endif
#else
            *p_err = DNSc_ERR_FAULT;
             goto exit;
#endif

             status = DNSc_STATUS_PENDING;
             break;


        case DNSc_STATE_TX_REQ_IPv4:
        case DNSc_STATE_TX_REQ_IPv6:
             DNScCache_Req(p_host, p_err);
             status = (*p_err == DNSc_ERR_TX_FAULT) ? DNSc_STATUS_FAILED : DNSc_STATUS_PENDING;
             break;


        case DNSc_STATE_TX_REQ_PTR_IPv4:
#ifdef  NET_IPv4_MODULE_EN
            (void)NetASCII_Str_to_IP( p_host->NamePtr,          /* Check if NamePtr is string representation of IP addr.*/
                                     &addr,
                                      NET_SOCK_ADDR_IPv4_SIZE,
                                     &net_err);

             if (net_err != NET_ASCII_ERR_NONE) {               /* If not, find host's first avail IPv4 addr as there...*/
                 p_item = p_host->AddrsFirstPtr;                /* ...might have been one already resolved by a prev ...*/
                                                                /* ...fwd req. Prioritize any preferred IP addr we find.*/
                 while (p_item != DEF_NULL) {
                     if (p_item->AddrPtr->Len == NET_IPv4_ADDR_LEN) {
                         resolved_addr_found = DEF_YES;
                         p_resolved_addr     = p_item->AddrPtr;

                         if (p_item->AddrPtr->RevPreferred) {
                             p_preferred_addr = p_resolved_addr;
                             break;
                         }
                     }
                     p_item = p_item->NextPtr;
                 }

                 if (p_preferred_addr != DEF_NULL) {
                     Mem_Copy(&addr,
                               p_preferred_addr->Addr,
                               NET_IPv4_ADDR_LEN);
                 } else if (p_resolved_addr != DEF_NULL) {
                     Mem_Copy(&addr,
                               p_resolved_addr->Addr,
                               NET_IPv4_ADDR_LEN);
                 } else {
                    *p_err = DNSc_ERR_INVALID_HOST_NAME;        /* If no resolved addr found, then host name is illegal.*/
                     goto exit;
                 }
             }

             p_addr_obj = DNScCache_AddrObjGet(&dnsc_err);      /* Alloc temp cache addr obj & populate it w/ IPv4 addr.*/
             if (dnsc_err == DNSc_ERR_NONE) {
                 p_addr_obj->Addr[0u] = ((addr & 0x000000FFu) >> (0u * DEF_INT_08_NBR_BITS));
                 p_addr_obj->Addr[1u] = ((addr & 0x0000FF00u) >> (1u * DEF_INT_08_NBR_BITS));
                 p_addr_obj->Addr[2u] = ((addr & 0x00FF0000u) >> (2u * DEF_INT_08_NBR_BITS));
                 p_addr_obj->Addr[3u] = ((addr & 0xFF000000u) >> (3u * DEF_INT_08_NBR_BITS));

                                                                /* Allocate addr item & assign it the temp addr obj  ...*/
                 if (resolved_addr_found == DEF_NO) {           /* ...once we've determined that PTR req is valid,   ...*/
                     p_item = DNScCache_AddrItemGet(&dnsc_err); /* ...that the addr was not found and that a new req ...*/
                     if (dnsc_err == DNSc_ERR_NONE) {           /* ...is needed.                                        */
                         p_addr_obj->Len               = NET_IPv4_ADDR_LEN;
                         p_item->AddrPtr               = p_addr_obj;
                         p_item->AddrPtr->RevPreferred = DEF_YES;
                         p_item->NextPtr               = DEF_NULL;
                         p_host->AddrsFirstPtr         = p_item;/* Point host's first addr to allocated cache addr item.*/
                     } else {
                         status = DNSc_STATUS_FAILED;
                        *p_err  = DNSc_ERR_MEM_ALLOC;
                         DNScCache_AddrObjFree(p_addr_obj);
                         goto exit;
                     }
                 } else {
                     DNScCache_AddrObjFree(p_addr_obj);         /* Discard 'p_addr_obj' as it is no longer needed.      */
                 }
                                                                /* Convert IPv4 addr to its dotted str representation...*/
                                                                /* ...& set it in host struct's .ReverseNamePtr field.  */
                 addr = NET_UTIL_VAL_SWAP_ORDER_32(addr);
                 NetASCII_IPv4_to_Str( addr,
                                       p_host->ReverseNamePtr,
                                       DEF_NO,
                                      &net_err);
                                                                /* To convert request to reverse lookup (PTR) type,...  */
                                                                /* ...append mapping domain to .ReverseNamePtr field.   */
                 len = Str_Len_N(p_host->ReverseNamePtr, p_host->NameLenMax);

                 if ((p_host->NameLenMax - len) <= DNSc_REVERSE_MAPPING_DOMAIN_IPv4_STR_LEN) {
                     status = DNSc_STATUS_FAILED;
                    *p_err  = DNSc_ERR_INVALID_HOST_NAME;
                     goto exit;
                 }
                 p_host->State  = DNSc_STATE_TX_REQ_PTR_IPv4;
                 p_reverse_name = Str_Cat_N(p_host->ReverseNamePtr,
                                            DNSc_REVERSE_MAPPING_DOMAIN_IPv4_STR,
                                            DNSc_REVERSE_MAPPING_DOMAIN_IPv4_STR_LEN);

                 Str_Copy_N(p_host->ReverseNamePtr, p_reverse_name, p_host->NameLenMax);
             } else {
                 status = DNSc_STATUS_FAILED;
                *p_err  = DNSc_ERR_MEM_ALLOC;
                 goto exit;
             }

             DNScCache_Req(p_host, p_err);
             status = DNSc_STATUS_PENDING;
#endif
             break;



        case DNSc_STATE_TX_REQ_PTR_IPv6:
#ifdef  NET_IPv6_MODULE_EN
            (void)NetASCII_Str_to_IP( p_host->NamePtr,          /* Check if NamePtr is string representation of IP addr.*/
                                     &addr_ipv6,
                                      NET_IPv6_ADDR_LEN,
                                     &net_err);
             if (net_err != NET_ASCII_ERR_NONE) {
                 p_item = p_host->AddrsFirstPtr;                /* If not, find host's first avail IPv6 addr as there...*/
                                                                /* ...might have been one already resolved by a prev ...*/
                 while (p_item != DEF_NULL) {                   /* ...fwd req. Prioritize any preferred IP addr we find.*/
                     if (p_item->AddrPtr->Len == NET_IPv6_ADDR_LEN) {
                         resolved_addr_found = DEF_YES;
                         p_resolved_addr = p_item->AddrPtr;
                         if (p_item->AddrPtr->RevPreferred) {
                             p_preferred_addr = p_resolved_addr;
                             break;
                         }
                     }
                     p_item = p_item->NextPtr;
                 }

                 if (p_preferred_addr != DEF_NULL) {
                     Mem_Copy(&addr_ipv6,
                               p_preferred_addr->Addr,
                               NET_IPv6_ADDR_LEN);
                 } else if (p_resolved_addr != DEF_NULL) {
                     Mem_Copy(&addr_ipv6,
                               p_resolved_addr->Addr,
                               NET_IPv6_ADDR_LEN);
                 } else {
                    *p_err = DNSc_ERR_INVALID_HOST_NAME;        /* If no resolved addr found, then host name is illegal.*/
                     goto exit;
                 }
             }

             p_addr_obj = DNScCache_AddrObjGet(&dnsc_err);      /* Alloc temp cache addr obj & populate it w/ IPv6 addr.*/
             if (dnsc_err == DNSc_ERR_NONE) {
                 Mem_Clr(p_host->ReverseNamePtr, p_host->NameLenMax);

                 for (CPU_INT16U i = NET_IPv6_ADDR_LEN; i > 0; i--) {  /* Swap addr bytes.                              */
                      p_addr_obj->Addr[i - 1u] = addr_ipv6.Addr[NET_IPv6_ADDR_LEN - i];
                 }
                 CPU_INT16U i = 0;                              /* Construct reverse IPv6 host name for PTR request.    */
                 for (CPU_INT16U j = 0u; i < NET_IPv6_ADDR_LEN; j += 4u) {
                      CPU_CHAR prepend = ((p_addr_obj->Addr[i] == 0u) || ((p_addr_obj->Addr[i] > 0) && (p_addr_obj->Addr[i] < DEF_NBR_BASE_HEX))) ? '0' : DEF_NULL;
                      Str_FmtNbr_Int32U( p_addr_obj->Addr[i],
                                         2u,
                                         DEF_NBR_BASE_HEX,
                                         prepend,
                                         DEF_YES,
                                         DEF_NO,
                                        (p_host->ReverseNamePtr + j));

                     *(p_host->ReverseNamePtr + j + 2u) = *(p_host->ReverseNamePtr + j);
                     *(p_host->ReverseNamePtr + j)      = *(p_host->ReverseNamePtr + j + 1u);
                     *(p_host->ReverseNamePtr + j + 1u) = '.';

                      if (j < (4 * NET_IPv6_ADDR_LEN) - 4u) {
                        *(p_host->ReverseNamePtr + j + 3u) = '.';
                      }
                      i++;
                 }

                 if (resolved_addr_found == DEF_NO) {
                     p_item = DNScCache_AddrItemGet(&dnsc_err); /* Alloc new address item since we've determined that...*/
                                                                /* ... hostname is valid but a new PTR req is required. */
                     if (dnsc_err == DNSc_ERR_NONE) {
                                                                /* If name was string representation, convert back to...*/
                         if (net_err == NET_ASCII_ERR_NONE) {   /* ...host order for DNScCache_HostNameCmp() comparison.*/
                             for (CPU_INT16U i = 0u; i < NET_IPv6_ADDR_LEN; i++) {
                                  p_addr_obj->Addr[i] = addr_ipv6.Addr[i];
                             }
                         }
                         p_addr_obj->Len               = NET_IPv6_ADDR_LEN;
                         p_item->AddrPtr               = p_addr_obj; /* Keep temp addr obj & assign it to new addr item.*/

                                                                     /* Flag addr as the preferred reverse resolution...*/
                         p_item->AddrPtr->RevPreferred = DEF_YES;    /*...IPv6 addr since we couldn't find one resolved.*/
                         p_item->NextPtr               = DEF_NULL;
                         p_host->AddrsFirstPtr         = p_item;     /* Point host's first addr to new cache addr item. */

                     } else {
                         status = DNSc_STATUS_FAILED;
                        *p_err  = DNSc_ERR_MEM_ALLOC;
                         DNScCache_AddrObjFree(p_addr_obj);
                         goto exit;
                     }
                 } else {
                     DNScCache_AddrObjFree(p_addr_obj);         /* If addr was found in cache, discard temp addr obj.   */
                 }
                                                                /* To convert request to reverse lookup (PTR) type,...  */
                                                                /* ...append mapping domain to .ReverseNamePtr field.   */
                 len = Str_Len_N(p_host->ReverseNamePtr, p_host->NameLenMax);

                 if ((p_host->NameLenMax - len) <= DNSc_REVERSE_MAPPING_DOMAIN_IPv6_STR_LEN) {
                     status = DNSc_STATUS_FAILED;
                    *p_err  = DNSc_ERR_INVALID_HOST_NAME;
                     goto exit;
                 }

                 p_host->State  = DNSc_STATE_TX_REQ_PTR_IPv6;
                 p_reverse_name = Str_Cat_N(p_host->ReverseNamePtr,
                                            DNSc_REVERSE_MAPPING_DOMAIN_IPv6_STR,
                                            DNSc_REVERSE_MAPPING_DOMAIN_IPv6_STR_LEN);

                 Str_Copy_N(p_host->ReverseNamePtr, p_reverse_name, p_host->NameLenMax);
             } else {
                 status = DNSc_STATUS_FAILED;
                *p_err  = DNSc_ERR_MEM_ALLOC;
                 goto exit;
             }
             DNScCache_Req(p_host, p_err);
             status = DNSc_STATUS_PENDING;
#endif
             break;


        case DNSc_STATE_RX_RESP_IPv4:
        case DNSc_STATE_RX_RESP_IPv6:
        case DNSc_STATE_RX_RESP_PTR_IPv4:
        case DNSc_STATE_RX_RESP_PTR_IPv6:
             status = DNScCache_Resp(p_cfg, p_host, p_err);
             break;


        case DNSc_STATE_RESOLVED:
             status = DNSc_STATUS_RESOLVED;
            *p_err  = DNSc_ERR_NONE;
             break;


        case DNSc_STATE_FREE:
        default:
             status = DNSc_STATUS_FAILED;
            *p_err  = DNSc_ERR_FAULT;
             goto exit;
    }


    switch (status) {
        case DNSc_STATUS_PENDING:
             break;

        case DNSc_STATUS_RESOLVED:
        case DNSc_STATUS_FAILED:
        default:
             DNSc_ReqClose(p_host->SockID);
             break;
    }


exit:
    return (status);
}

/*
*********************************************************************************************************
*                                            DNScCache_Req()
*
* Description : Send an host resolution request.
*
* Argument(s) : p_host  Pointer to the host object.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE   No error.
*                           DNSc_ERR_FAULT  Unknown error (should not occur).
*
*                           RETURNED BY DNScReq_TxReq():
*                               See DNScReq_TxReq() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_Resolve().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScCache_Req (DNSc_HOST_OBJ  *p_host,
                             DNSc_ERR       *p_err)
{
    DNSc_REQ_TYPE  req_type;


    switch (p_host->State) {
        case DNSc_STATE_TX_REQ_IPv4:
             req_type = DNSc_REQ_TYPE_IPv4;
             break;

        case DNSc_STATE_TX_REQ_IPv6:
             req_type = DNSc_REQ_TYPE_IPv6;
             break;

        case DNSc_STATE_TX_REQ_PTR_IPv4:
             req_type = DNSc_REQ_TYPE_PTR_IPv4;
             break;

        case DNSc_STATE_TX_REQ_PTR_IPv6:
             req_type = DNSc_REQ_TYPE_PTR_IPv6;
             break;

        default:
            *p_err = DNSc_ERR_FAULT;
             goto exit;
    }


    if ((req_type == DNSc_REQ_TYPE_PTR_IPv4) || (req_type == DNSc_REQ_TYPE_PTR_IPv6)) {
        p_host->QueryID = DNScReq_TxReq(p_host->ReverseNamePtr, p_host->SockID, DNSc_QUERY_ID_NONE, req_type, p_err);
    } else {
        p_host->QueryID = DNScReq_TxReq(p_host->NamePtr, p_host->SockID, DNSc_QUERY_ID_NONE, req_type, p_err);
    }
    switch (*p_err) {
        case DNSc_ERR_NONE:
             break;

        case DNSc_ERR_IF_LINK_DOWN:
             p_host->State = DNSc_STATE_IF_SEL;
             goto exit_no_err;

        default:
             goto exit;
    }

    switch (p_host->State) {
        case DNSc_STATE_TX_REQ_IPv4:
             p_host->State = DNSc_STATE_RX_RESP_IPv4;
             break;

        case DNSc_STATE_TX_REQ_IPv6:
             p_host->State = DNSc_STATE_RX_RESP_IPv6;
             break;

        case DNSc_STATE_TX_REQ_PTR_IPv4:
             p_host->State = DNSc_STATE_RX_RESP_PTR_IPv4;
             break;

        case DNSc_STATE_TX_REQ_PTR_IPv6:
             p_host->State = DNSc_STATE_RX_RESP_PTR_IPv6;
             break;

        default:
            *p_err = DNSc_ERR_FAULT;
             goto exit;
    }


    p_host->TS_ms = NetUtil_TS_Get_ms();
    p_host->ReqCtr++;


exit_no_err:
   *p_err = DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                           DNScCache_Resp()
*
* Description : Receive host resolution request response.
*
* Argument(s) : p_cfg   Pointer to DNSc's configuration.
*
*               p_host  Pointer to the host object.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE   No error.
*                           DNSc_ERR_FAULT  Unknown error (should not occur).
*
*                           RETURNED BY DNScReq_TxReq():
*                               See DNScReq_TxReq() for additional return error codes.
*
* Return(s)   : Resolution status:
*                       DNSc_STATUS_PENDING         Host resolution is pending, call again to see the status. (Processed by DNSc's task)
*                       DNSc_STATUS_RESOLVED        Host is resolved.
*                       DNSc_STATUS_FAILED          Host resolution has failed.
*
* Caller(s)   : DNScCache_Resolve().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  DNSc_STATUS  DNScCache_Resp (const  DNSc_CFG       *p_cfg,
                                            DNSc_HOST_OBJ  *p_host,
                                            DNSc_ERR       *p_err)
{
    DNSc_STATUS      status;
    NET_TS_MS        ts_cur_ms;
    NET_TS_MS        ts_delta_ms;
    NET_TS_MS        timeout_ms   = (NET_TS_MS)p_cfg->ReqRetryTimeout_ms;
    CPU_INT08U       req_retry    =  p_cfg->ReqRetryNbrMax;
    CPU_BOOLEAN      re_tx        =  DEF_NO;
    CPU_BOOLEAN      change_state =  DEF_NO;
    DNSc_ADDR_ITEM  *p_addr_item;


    if (p_host->ReqCfgPtr != DEF_NULL) {
        timeout_ms = p_host->ReqCfgPtr->ReqTimeout_ms;
        req_retry  = p_host->ReqCfgPtr->ReqRetry;
    }

    status = DNScReq_RxResp(p_cfg, p_host, p_host->SockID, p_host->QueryID, p_err);
    switch (*p_err) {
        case DNSc_ERR_NONE:
             change_state = DEF_YES;
             break;

        case DNSc_ERR_RX:
             if (p_host->ReqCtr >= req_retry) {
                                                                /* If reverse lookup, free resources obtained by... */
                                                                /* ...DNScCache_Resolve() if server is unresponsive.*/
                 p_addr_item = p_host->AddrsFirstPtr;

                 if (p_host->State == DNSc_STATE_RX_RESP_PTR_IPv4) {
                     while (p_addr_item != DEF_NULL) {
                         if (p_addr_item->AddrPtr->Len == NET_IPv4_ADDR_LEN) {
                             DNScCache_AddrItemFree(p_addr_item);
                         }
                         p_addr_item = p_addr_item->NextPtr;
                     }
                 }

                 if (p_host->State == DNSc_STATE_RX_RESP_PTR_IPv6) {
                     while (p_addr_item != DEF_NULL) {
                         if (p_addr_item->AddrPtr->Len == NET_IPv6_ADDR_LEN) {
                             DNScCache_AddrItemFree(p_addr_item);
                         }
                         p_addr_item = p_addr_item->NextPtr;
                     }
                 }

                 p_host->AddrsFirstPtr = (void *)0;
                 status                = DNSc_STATUS_FAILED;
                 p_host->State         = DNSc_STATE_FAILED;
                *p_err                 = DNSc_ERR_NO_SERVER;

                 goto exit;

             } else {
                 ts_cur_ms   = NetUtil_TS_Get_ms();
                 ts_delta_ms = ts_cur_ms - p_host->TS_ms;
                 if (ts_delta_ms >= timeout_ms) {
                     re_tx        = DEF_YES;
                     change_state = DEF_YES;
                 }
             }
             break;

        default:

             goto exit;
    }

    if (change_state == DEF_YES) {
        switch (p_host->State) {
            case DNSc_STATE_RX_RESP_PTR_IPv4:
            case DNSc_STATE_RX_RESP_PTR_IPv6:
                 if (re_tx != DEF_YES) {
                     p_host->State = DNSc_STATE_RESOLVED;
                     status        = DNSc_STATUS_RESOLVED;
                 } else {
                     p_host->State = (p_host->State == DNSc_STATE_RX_RESP_PTR_IPv4) ?
                                      DNSc_STATE_TX_REQ_PTR_IPv4                    :
                                      DNSc_STATE_TX_REQ_PTR_IPv6;
                 }
                 break;

            case DNSc_STATE_RX_RESP_IPv4:
                 if (re_tx == DEF_YES) {
                     p_host->State = DNSc_STATE_TX_REQ_IPv4;
                 } else {
#ifdef  NET_IPv6_MODULE_EN
                     p_host->ReqCtr = 0;
                     p_host->State  = DNSc_STATE_TX_REQ_IPv6;
                     status         = DNSc_STATUS_PENDING;
#else
                     p_host->State = DNSc_STATE_RESOLVED;
                     status        = DNSc_STATUS_RESOLVED;
#endif
                 }
                 break;

            case DNSc_STATE_RX_RESP_IPv6:
                 if (re_tx == DEF_YES) {
                     p_host->State = DNSc_STATE_TX_REQ_IPv6;
                     status        = DNSc_STATUS_PENDING;

                 } else if (status != DNSc_STATUS_RESOLVED) {   /* If the resolution has failed, let try on another     */
                     p_host->State = DNSc_STATE_IF_SEL;         /* interface. It may be possible to reach the DNS       */
                     status        = DNSc_STATUS_PENDING;       /* server using another link.                           */

                 } else {
                     p_host->State = DNSc_STATE_RESOLVED;
                     status        = DNSc_STATUS_RESOLVED;
                 }
                 break;

            default:
                 status = DNSc_STATUS_FAILED;
                *p_err  = DNSc_ERR_FAULT;
                 goto exit;
        }
    }


exit:
    return (status);
}

