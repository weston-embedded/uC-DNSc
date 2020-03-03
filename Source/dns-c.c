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
*                                             DNS CLIENT
*
* Filename : dns-c.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) This file implements a basic DNS client based on RFC #1035.  It provides the
*                mechanism used to retrieve an IP address from a given host name.
*
*            (2) Assumes the following versions (or more recent) of software modules are included
*                in the project build :
*
*                (a) uC/TCP-IP V3.00
*                (b) uC/CPU    V1.30
*                (c) uC/LIB    V1.37
*                (d) uC/Common-KAL V1.00.00
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#define    MICRIUM_SOURCE
#define    DNSc_MODULE
#include  "dns-c.h"
#include  "dns-c_req.h"
#include  "dns-c_cache.h"
#include  "dns-c_task.h"
#include  <Source/net_ascii.h>


/*
*********************************************************************************************************
*                                             DNSc_Init()
*
* Description : Initialize DNSc module.
*
* Argument(s) : p_cfg       Pointer to DNSc's configuration.
*
*               p_task_cfg  Pointer to a structure that contains the task configuration of the Asynchronous task.
*                           If Asynchronous mode is disabled this pointer should be set to DEF_NULL.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE           Server address successfully set.
*                               DNSc_ERR_NULL_PTR       Invalid pointer.
*
*                               RETURNED BY DNScCache_Init():
*                                   See DNScCache_Init() for additional return error codes.
*
*                               RETURNED BY DNScTask_Init():
*                                   See DNScTask_Init() for additional return error codes.
*
*                               RETURNED BY DNScReq_ServerInit():
*                                   See DNScReq_ServerInit() for additional return error codes.
*
* Return(s)   : none.
*
* Caller(s)   : Application.
*
* Note(s)     : (1) DNSc_Init() MUST be called PRIOR to using other DNSc functions.
*********************************************************************************************************
*/

void  DNSc_Init (const  DNSc_CFG       *p_cfg,
                 const  DNSc_CFG_TASK  *p_task_cfg,
                        DNSc_ERR       *p_err)
{
#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_cfg == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }
#endif

    DNScCache_Init(p_cfg, p_err);
    if (*p_err != DNSc_ERR_NONE) {
        goto exit;
    }

    DNScReq_ServerInit(p_cfg, p_err);
    if (*p_err != DNSc_ERR_NONE) {
        goto exit;
    }

    DNScTask_Init(p_cfg, p_task_cfg, p_err);
    if (*p_err != DNSc_ERR_NONE) {
        goto exit;
    }

exit:
    return;
}


/*
*********************************************************************************************************
*                                         DNSc_CfgServerByStr()
*
* Description : Configure DNS server that must be used by default using a string.
*
* Argument(s) : p_server    Pointer to a string that contains the IP address of the DNS server.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE           Server address successfully set.
*                               DNSc_ERR_NULL_PTR       Invalid pointer.
*
*                               RETURNED BY DNScCache_AddrObjSet():
*                                   See DNScCache_AddrObjSet() for additional return error codes.
*
*                               RETURNED BY DNScReq_ServerSet():
*                                   See DNScReq_ServerSet() for additional return error codes.

* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNSc_CfgServerByStr (CPU_CHAR  *p_server,
                           DNSc_ERR  *p_err)
{
    DNSc_ADDR_OBJ  ip_addr;


#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_err == DEF_NULL) {
        CPU_SW_EXCEPTION(DEF_NULL);
    }

    if (p_server == DEF_NULL) {
        *p_err = DNSc_ERR_NULL_PTR;
         goto exit;
    }
#endif

    DNScCache_AddrObjSet(&ip_addr, p_server, p_err);
    if (*p_err != DNSc_ERR_NONE) {
        goto exit;
    }


    DNScReq_ServerSet(&ip_addr, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }


   *p_err = DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNSc_CfgServerByAddr()
*
* Description : Configure DNS server that must be used by default using an address structure.
*
* Argument(s) : p_addr  Pointer to structure that contains the IP address of the DNS server.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Server address successfully set.
*                           DNSc_ERR_NULL_PTR       Invalid pointer.
*                           DNSc_ERR_ADDR_INVALID   Invalid IP address.
*
*                           RETURNED BY DNScCache_AddrObjSet():
*                               See DNScCache_AddrObjSet() for additional return error codes.
*
*                           RETURNED BY DNScReq_ServerSet():
*                               See DNScReq_ServerSet() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNSc_CfgServerByAddr (DNSc_ADDR_OBJ  *p_addr,
                            DNSc_ERR       *p_err)
{
#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_err == DEF_NULL) {
        CPU_SW_EXCEPTION(DEF_NULL);
    }

    if (p_addr == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }
#endif

    switch (p_addr->Len) {
        case NET_IPv4_ADDR_SIZE:
        case NET_IPv6_ADDR_SIZE:
             break;

        default:
            *p_err = DNSc_ERR_ADDR_INVALID;
             goto exit;
    }

    DNScReq_ServerSet(p_addr, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }


   *p_err = DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                         DNSc_GetServerByStr()
*
* Description : Get DNS server in string format that is configured to be use by default.
*
* Argument(s) : p_addr      Pointer to structure that will receive the IP address of the DNS server.
*
*               str_len_max Maximum string length.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE               Server address successfully returned.
*                           DNSc_ERR_INVALID_ARG        Invalid argument
*                           DNSc_ERR_ADDR_INVALID       Invalid server address.
*                           DNSc_ERR_FAULT              Unknown error.
*
*                           RETURNED BY DNScReq_ServerGet():
*                               See DNScReq_ServerGet() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNSc_GetServerByStr (CPU_CHAR    *p_str,
                           CPU_INT08U   str_len_max,
                           DNSc_ERR    *p_err)
{
    DNSc_ADDR_OBJ  addr;
    NET_ERR        err;


#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_err == DEF_NULL) {
        CPU_SW_EXCEPTION(DEF_NULL);
    }

    if (p_str == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }
#endif

    DNScReq_ServerGet(&addr, p_err);
    if (*p_err != DNSc_ERR_NONE) {
        goto exit;
    }

    switch (addr.Len) {
        case NET_IPv4_ADDR_LEN:
#ifdef  NET_IPv4_MODULE_EN
             if (str_len_max < NET_ASCII_LEN_MAX_ADDR_IPv4) {
                *p_err = DNSc_ERR_INVALID_ARG;
                 goto exit;
             }

             NetASCII_IPv4_to_Str(*(NET_IPv4_ADDR *)addr.Addr, p_str, DEF_NO, &err);
             if (err != NET_ASCII_ERR_NONE) {
                *p_err = DNSc_ERR_ADDR_INVALID;
                 goto exit;
             }
             break;
#else
            *p_err = DNSc_ERR_ADDR_INVALID;
             goto exit;

#endif

        case NET_IPv6_ADDR_LEN:
#ifdef  NET_IPv6_MODULE_EN
             if (str_len_max < NET_ASCII_LEN_MAX_ADDR_IPv6) {
                *p_err = DNSc_ERR_INVALID_ARG;
                 goto exit;
             }

             NetASCII_IPv6_to_Str((NET_IPv6_ADDR *)addr.Addr, p_str, DEF_NO, DEF_NO, &err);
             if (err != NET_ASCII_ERR_NONE) {
                *p_err = DNSc_ERR_ADDR_INVALID;
                 goto exit;
             }
             break;
#else
             *p_err = DNSc_ERR_ADDR_INVALID;
              goto exit;
#endif

        default:
            *p_err = DNSc_ERR_FAULT;
             goto exit;
    }


   *p_err = DNSc_ERR_NONE;


exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNSc_CfgServerByAddr()
*
* Description : Get DNS server in address object that is configured to be use by default.
*
* Argument(s) : p_addr  Pointer to structure that will receive the IP address of the DNS server.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Server address successfully returned.
*
*                           RETURNED BY DNScReq_ServerGet():
*                               See DNScReq_ServerGet() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNSc_GetServerByAddr (DNSc_ADDR_OBJ  *p_addr,
                            DNSc_ERR       *p_err)
{
#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_err == DEF_NULL) {
        CPU_SW_EXCEPTION(DEF_NULL);
    }

    if (p_addr == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        return;
    }
#endif

    DNScReq_ServerGet(p_addr, p_err);


    return;
}


/*
*********************************************************************************************************
*                                            DNSc_GetHost()
*
* Description : Convert string representation of a host name to its corresponding IP address using DNS
*               service.
*
* Argument(s) : p_host_name         Pointer to a string that contains the host name.
*
*               p_res_host_name     Pointer to a string that will receive the host name resulting from a reverse lookup
*                                   OR the canonical name resulting from a forward lookup with the DNSc_FLAG_CANON set.
*                                   This argument should be left DEF_NULL if a simple forward DNS request is desired.
*
*               res_hostname_len    String length of p_res_host_name. This argument should evaluate to 0 if a simple forward
*                                   DNS request is desired (with DNSc_FLAG_CANON cleared).
*
*               p_addrs             Pointer to arrays that will receive the IP address from this function.
*
*               p_addr_nbr          Pointer to a variable that contains how many address can be contained in the addresses
*                                   array and that will receive the number of addresses copied in the addresses array
*
*               flags               DNS client flag:
*
*                                       DNSc_FLAG_NONE              By default this function is blocking.
*                                       DNSc_FLAG_NO_BLOCK          Don't block (only possible if DNSc's task is enabled).
*                                       DNSc_FLAG_FORCE_CACHE       Take host from the cache, don't send new DNS request.
*                                       DNSc_FLAG_FORCE_RENEW       Force DNS request, remove existing entry in the cache.
*                                       DNSc_FLAG_FORCE_RESOLUTION  Force DNS to resolve given host name.
*                                       DNSc_FLAG_IPv4_ONLY         Return only IPv4 address(es).                (A     type).
*                                       DNSc_FLAG_IPv6_ONLY         Return only IPv6 address(es).                (AAAA  type).
*                                       DNSc_FLAG_REVERSE_LOOKUP    Issue a reverse DNS lookup for an IPv4 addr. (PTR   type).
*                                       DNSc_FLAG_CANON             Handle canonical name in DNS answer(s).      (CNAME type).
*
*               p_cfg               Pointer to a request configuration. Should be set to overwrite default DNS configuration
*                                   (such as DNS server, request timeout, etc.).
*                                   Must be set to DEF_NULL to use default configuration.
*
*               p_err               Pointer to variable that will receive the return error code from this function :
*
*                                       DNSc_ERR_NONE               Request successful issued or resolved.
*                                       DNSc_ERR_NULL_PTR           Invalid pointer.
*                                       DNSc_ERR_INVALID_ARG        Invalid argument.
*                                       DNSc_ERR_FAULT              Fault error.
*
*                                       RETURNED BY DNScCache_Srch():
*                                           See DNScCache_Srch() for additional return error codes.
*
*                                       RETURNED BY DNScCache_HostObjGet():
*                                           See DNScCache_HostObjGet() for additional return error codes.
*
*                                       RETURNED BY DNScTask_ProcessHostReq():
*                                           See DNScTask_ProcessHostReq() for additional return error codes.
*
* Return(s)   : Resolution status:
*                       DNSc_STATUS_PENDING         Host resolution is pending, call again to see the status. (Processed by DNSc's task)
*                       DNSc_STATUS_RESOLVED        Host is resolved.
*                       DNSc_STATUS_FAILED          Host resolution has failed.
*
* Caller(s)   : Application.
*
* Note(s)     : (1) If the DNSc_FLAG_REVERSE_LOOKUP is set, this function will issue a reverse DNS request
*                   (of type PTR) and point the p_rev_host_name argument to the resolved host name.
*
*               (2) If the DNSc_FLAG_CANON flag is set, this function will handle canonical names and update
*                   the host entry's .CanonicalNamePtr until a TYPE A, TYPE AAAA answer is found or the
*                   end of the message is reached.
*********************************************************************************************************
*/

DNSc_STATUS  DNSc_GetHost (const  CPU_CHAR       *p_host_name,
                                  CPU_CHAR       *p_res_host_name,
                                  CPU_INT32U      res_hostname_len,
                                  DNSc_ADDR_OBJ  *p_addrs,
                                  CPU_INT08U     *p_addr_nbr,
                                  DNSc_FLAGS      flags,
                                  DNSc_REQ_CFG   *p_cfg,
                                  DNSc_ERR       *p_err)
{
    NET_IP_ADDR_FAMILY   ip_family;
    DNSc_ADDR_OBJ        local_pref_addr;
    DNSc_REQ_CFG         local_req_cfg;
    DNSc_STATUS          status   = DNSc_STATUS_FAILED;
    CPU_BOOLEAN          flag_set = DEF_NO;
    CPU_BOOLEAN          is_canonical;
    CPU_BOOLEAN          is_force_res;
    CPU_BOOLEAN          is_reverse;
    CPU_INT08U           addr_nbr;
    CPU_SIZE_T           len;
    DNSc_HOST_OBJ       *p_host;
    NET_ERR              err;


                                                                /* ------------------ VALIDATE ARGS ------------------- */
#if (DNSc_CFG_ARG_CHK_EXT_EN == DEF_ENABLED)
    if (p_err == DEF_NULL) {
        CPU_SW_EXCEPTION(DEF_NULL);
    }

    if (p_host_name == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }

    len = Str_Len_N(p_host_name, DNSc_DFLT_HOST_NAME_LEN);

    if (len == 0u) {
       *p_err = DNSc_ERR_INVALID_ARG;
        goto exit;
    }

    if (p_addr_nbr == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }

    if (*p_addr_nbr == 0u) {
       *p_err = DNSc_ERR_INVALID_ARG;
        goto exit;
    }

    flag_set = (DEF_BIT_IS_SET(flags, DNSc_FLAG_UPDATE_PREF) || /* Caller should never use these internal flags.        */
                DEF_BIT_IS_SET(flags, DNSc_FLAG_RESET_REQ));
    if (flag_set == DEF_TRUE) {
       *p_err = DNSc_ERR_INVALID_ARG;
        goto exit;
    }

    flag_set = DEF_BIT_IS_SET(flags, DNSc_FLAG_REVERSE_LOOKUP);
    if (flag_set == DEF_TRUE) {
        if (p_res_host_name == DEF_NULL) {
           *p_err = DNSc_ERR_NULL_PTR;
            goto exit;
        }
    }

    if (p_addrs == DEF_NULL) {
       *p_err = DNSc_ERR_NULL_PTR;
        goto exit;
    }

#ifndef  DNSc_TASK_MODULE_EN
    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_NO_BLOCK)) {
       *p_err = DNSc_ERR_INVALID_CFG;
        goto exit;
#ifdef DNSc_SIGNAL_TASK_MODULE_EN
    } else {
       *p_err = DNSc_ERR_INVALID_CFG;
        goto exit;
#endif
    }
#endif
    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_FORCE_CACHE) &&
        DEF_BIT_IS_SET(flags, DNSc_FLAG_FORCE_RENEW)) {
       *p_err = DNSc_ERR_INVALID_CFG;
        goto exit;
    }

    if (DEF_BIT_IS_SET(flags, DNSc_FLAG_CANON) &&
        DEF_BIT_IS_SET(flags, DNSc_FLAG_REVERSE_LOOKUP)) {
       *p_err = DNSc_ERR_INVALID_CFG;
        goto exit;
    }
#endif

    is_canonical =  DEF_BIT_IS_SET(flags, DNSc_FLAG_CANON);
    is_reverse   =  DEF_BIT_IS_SET(flags, DNSc_FLAG_REVERSE_LOOKUP);
    addr_nbr     = *p_addr_nbr;

                                                                /* First check to see if the incoming host name is  ... */
                                                                /* ...simply a decimal-dot-formatted IP address. If ... */
                                                                /* ...it is in that format and this is a forward DNS... */
                                                                /* ...request, then just convert it and return.         */
    ip_family = NetASCII_Str_to_IP((CPU_CHAR *)p_host_name,
                                               local_pref_addr.Addr,
                                               sizeof(local_pref_addr.Addr),
                                              &err);

    if (p_cfg != DEF_NULL) {                                    /* Populate request configuration based on p_cfg value. */
        local_req_cfg.ServerAddrPtr = p_cfg->ServerAddrPtr;
        local_req_cfg.ServerPort    = p_cfg->ServerPort;
        local_req_cfg.ReqTimeout_ms = p_cfg->ReqTimeout_ms;
        local_req_cfg.ReqRetry      = p_cfg->ReqRetry;
        local_req_cfg.TaskDly_ms    = p_cfg->TaskDly_ms;
    } else {
        local_req_cfg.ServerAddrPtr = (DNSc_ADDR_OBJ *)DEF_NULL;
        local_req_cfg.ServerPort    = NET_PORT_NBR_NONE;
        local_req_cfg.ReqTimeout_ms = DNSc_Cfg.ReqRetryTimeout_ms;
        local_req_cfg.ReqRetry      = DNSc_Cfg.ReqRetryNbrMax;
        local_req_cfg.TaskDly_ms    = DNSc_Cfg.TaskDly_ms;
    }

    local_req_cfg.ReqFlags = DNSc_FLAG_NONE;

    DEF_BIT_SET(local_req_cfg.ReqFlags, flags);

    if (is_reverse == DEF_YES) {
        is_force_res = DEF_YES;                                 /* Ignore DNSc_FLAG_FORCE_RESOLUTION flag.              */

        DEF_BIT_SET(local_req_cfg.ReqFlags,                     /* Ensure that every addr found by reverse host srch ...*/
                    DNSc_FLAG_UPDATE_PREF);                     /* ...is flagged as the preferred reverse lookup addr.  */

                                                                /* Set appropriate reverse .ReqType in 'local_req_cfg'. */
        if (DEF_BIT_IS_SET(local_req_cfg.ReqFlags, DNSc_FLAG_IPv4_ONLY)) {
            local_req_cfg.ReqType = DNSc_REQ_TYPE_PTR_IPv4;
        } else if (DEF_BIT_IS_SET(local_req_cfg.ReqFlags, DNSc_FLAG_IPv6_ONLY)) {
            local_req_cfg.ReqType = DNSc_REQ_TYPE_PTR_IPv6;
        } else {
            if (err == NET_ASCII_ERR_NONE) {
                local_req_cfg.ReqType = (ip_family == NET_IP_ADDR_FAMILY_IPv4) ?
                                         DNSc_REQ_TYPE_PTR_IPv4                :
                                         DNSc_REQ_TYPE_PTR_IPv6;
            }
        }
    } else {
        is_force_res = DEF_BIT_IS_SET(flags, DNSc_FLAG_FORCE_RESOLUTION);
    }


    if (err == NET_ASCII_ERR_NONE) {
                                                                /* Create version of preferred IP addr to resolve  ...  */
                                                                /* ...built from 'p_host_name' for later comparison...  */
                                                                /* ...to the cache's preferred reverse lookup addr.     */
        local_pref_addr.Len          = (ip_family == NET_IP_ADDR_FAMILY_IPv4) ?
                                        NET_IPv4_ADDR_LEN                     :
                                        NET_IPv6_ADDR_LEN;
        local_pref_addr.RevPreferred = DEF_TRUE;



        if ((is_reverse == DEF_NO) && (is_force_res == DEF_YES)) {
           *p_err = DNSc_ERR_INVALID_CFG;                       /* Prevent fwd DNS request for decimal dot-formatted... */
            goto exit;                                          /* ...IP address if DNSc_FLAG_FORCE_RESOLUTION is set.  */
        }
        if (is_force_res == DEF_NO) {
            switch (ip_family) {
                case NET_IP_ADDR_FAMILY_IPv4:
                     Mem_Copy(p_addrs[0].Addr,
                              local_pref_addr.Addr,
                              local_pref_addr.Len);

                     p_addrs[0].Len = NET_IPv4_ADDR_LEN;
                     status         = DNSc_STATUS_RESOLVED;
                    *p_addr_nbr     = 1u;
                    *p_err          = DNSc_ERR_NONE;
                     goto exit;


                case NET_IP_ADDR_FAMILY_IPv6:
                     Mem_Copy(p_addrs[0].Addr,
                              local_pref_addr.Addr,
                              local_pref_addr.Len);

                     p_addrs[0].Len = NET_IPv6_ADDR_LEN;
                     status         = DNSc_STATUS_RESOLVED;
                    *p_addr_nbr     = 1u;
                    *p_err          = DNSc_ERR_NONE;
                     goto exit;


                default:
                    break;
            }
        }
    } else if (err == NET_ASCII_ERR_IP_FAMILY_NOT_PRESENT) {    /* If reverse addr requested but its corresponding IP...*/
       *p_err  = DNSc_ERR_ADDR_INVALID;                         /*...module not enabled, return to caller with an error.*/
        status = DNSc_STATUS_FAILED;
        goto exit;
    } else {
        Mem_Clr(&local_pref_addr, sizeof(local_pref_addr));
    }

    flag_set = DEF_BIT_IS_SET(local_req_cfg.ReqFlags, DNSc_FLAG_FORCE_CACHE);
    if (flag_set == DEF_YES) {
        status = DNScCache_Srch( p_host_name,
                                &p_host,
                                 p_addrs,
                                 addr_nbr,
                                 p_addr_nbr,
                                 local_req_cfg.ReqFlags,
                                 p_err);
        goto exit;
    }

    flag_set = DEF_BIT_IS_SET(local_req_cfg.ReqFlags, DNSc_FLAG_FORCE_RENEW);
    if (flag_set == DEF_NO) {
                                                                /* ---------- SRCH IN EXISTING CACHE ENTRIES ---------- */
        DEF_BIT_CLR(local_req_cfg.ReqFlags,                     /* Make sure this search does NOT modify the cache's... */
                    DNSc_FLAG_UPDATE_PREF);                     /*...current preferred IP addr for reverse lookups.     */

        status = DNScCache_Srch( p_host_name,
                                &p_host,
                                 p_addrs,
                                 addr_nbr,
                                 p_addr_nbr,
                                 local_req_cfg.ReqFlags,
                                 p_err);

        DEF_BIT_SET(local_req_cfg.ReqFlags,
                    DNSc_FLAG_UPDATE_PREF);

        switch (status) {
            case DNSc_STATUS_PENDING:
            case DNSc_STATUS_RESOLVED:
                 if (is_reverse == DEF_YES) {
                     if (p_host->State == DNSc_STATE_RESOLVED) {
                         len          = Str_Len_N(p_host->ReverseNamePtr, p_host->NameLenMax);
                         is_force_res = (len == 0u);
                                                                /* Check returned addrs & determine if a resolution  ...*/
                         if ((len != 0u)) {                     /*...is req'd based on a match between a preferred IP...*/
                                                                /*...addr in the cache & 'local_pref_addr'.             */
                              for (CPU_INT32U i = 0; i < *p_addr_nbr; i++) {
                                   is_force_res  = (p_addrs[i].RevPreferred == DEF_FALSE);
                                   is_force_res &= Mem_Cmp(&local_pref_addr.Addr,
                                                           &p_addrs[i].Addr,
                                                            p_addrs[i].Len);

                                                                /* If we cannot match the addr in 'p_host_name' to a ...*/
                                                                /*...preferred addr in 'p_addrs', force a new reverse...*/
                                                                /*...resol. for non-preferred addr in 'local_pref_addr'.*/
                                   if (is_force_res == DEF_TRUE) {
                                       break;
                                   }
                              }
                         }
                                                                /* Allocate object from the Host Reverse Name Pool & ...*/
                                                                /*...reset DNSc request state machine.                  */
                         if (is_force_res == DEF_TRUE) {
                             DEF_BIT_SET(local_req_cfg.ReqFlags, DNSc_FLAG_RESET_REQ);
                             p_host = DNScCache_HostObjGet(p_host_name, local_req_cfg.ReqFlags, &local_req_cfg, p_err);

                             if (*p_err != DNSc_ERR_NONE) {
                                 goto exit_free_host;
                             }

                             DEF_BIT_CLR(p_host->ReqCfgPtr->ReqFlags, DNSc_FLAG_RESET_REQ);
                             DEF_BIT_CLR(local_req_cfg.ReqFlags,      DNSc_FLAG_RESET_REQ);
                         } else {
                             goto exit_copy_name;
                         }
                     }
                                                                /* Issue new rev resolution (DNSc_STATE_INIT_REQ) OR ...*/
                     status = DNScTask_HostResolve(p_host,      /*...continue resolving prev one by advancing its state.*/
                                                   p_host->ReqCfgPtr->ReqFlags,
                                                   p_host->ReqCfgPtr,
                                                   p_err);

                     goto exit_copy_name;
                 }

                 if (is_canonical == DEF_YES) {                 /* Avoid unnecessary resolution and copy canonical name.*/
                     goto exit_copy_name;
                 }
                 goto exit;

            case DNSc_STATUS_FAILED:
                 break;

            default:
                *p_err = DNSc_ERR_FAULT;
                 goto exit;
        }

    } else {
        DNScCache_HostSrchRemove(p_host_name, p_err);
    }

                                                                /* ----------- ACQUIRE HOST OBJ FOR THE REQ ----------- */
    p_host = DNScCache_HostObjGet(p_host_name, local_req_cfg.ReqFlags, &local_req_cfg, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         status = DNSc_STATUS_FAILED;
         goto exit;
    }

    status = DNScTask_HostResolve(p_host, local_req_cfg.ReqFlags, &local_req_cfg, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }

    switch (status) {
#ifdef   DNSc_TASK_MODULE_EN
        case DNSc_STATUS_NONE:
#endif
        case DNSc_STATUS_PENDING:
             goto exit;

        case DNSc_STATUS_RESOLVED:
        case DNSc_STATUS_UNKNOWN:
             break;

        case DNSc_STATUS_FAILED:
             goto exit_free_host;

        default:
            *p_err = DNSc_ERR_FAULT;
             goto exit;
    }

    status = DNScCache_Srch( p_host_name,
                            &p_host,
                             p_addrs,
                             addr_nbr,
                             p_addr_nbr,
                             local_req_cfg.ReqFlags,
                             p_err);


exit_copy_name:

    if (is_reverse == DEF_YES) {
        if (p_host->AddrsCount == 1u) {                         /* If only one resolved addr in host, set as preferred. */
            p_host->AddrsFirstPtr->AddrPtr->RevPreferred = DEF_TRUE;
        }
        if (p_host->State == DNSc_STATE_RESOLVED) {
            Str_Copy_N(p_res_host_name,                         /* Copy reverse lookup name. (See Note #1).             */
                       p_host->ReverseNamePtr,
                       res_hostname_len);

            status = DNSc_STATUS_RESOLVED;
        }
    } else {
        if ((is_canonical == DEF_YES) && (status == DNSc_STATUS_RESOLVED)) {
        Str_Copy_N(p_res_host_name,                             /* Copy canonical name. (See Note #2).                  */
                   p_host->CanonicalNamePtr,
                   res_hostname_len);
        }
    }

    goto exit;


exit_free_host:
    DNScCache_HostObjFree(p_host);

exit:
    return (status);
}


/*
*********************************************************************************************************
*                                            DNSc_CacheClr()
*
* Description : Flush DNS cache.
*
* Argument(s) : p_err   Pointer to variable that will receive the return error code from this function :
*
*                           RETURNED BY DNScCache_Clr():
*                               See DNScCache_Clr() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : none.
*********************************************************************************************************
*/

void  DNSc_CacheClrAll (DNSc_ERR  *p_err)
{
    DNScCache_Clr(p_err);
}


/*
*********************************************************************************************************
*                                          DNSc_CacheClrHost()
*
* Description : Remove a host from the cache.
*
* Argument(s) : p_host_name Pointer to a string that contains the host name to remove from the cache.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               RETURNED BY DNScCache_HostSrchRemove():
*                                   See DNScCache_HostSrchRemove() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNSc_CacheClrHost (CPU_CHAR  *p_host_name,
                         DNSc_ERR  *p_err)
{
    DNScCache_HostSrchRemove(p_host_name, p_err);
}

