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
*                                       DNS CLIENT REQ MODULE
*
* Filename : dns-c_req.h
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) Assumes the following versions (or more recent) of software modules are included
*                in the project build :
*
*                (a) uC/TCPIP    V3.00.00
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*********************************************************************************************************
*                                               MODULE
*********************************************************************************************************
*********************************************************************************************************
*/

#ifndef  DNSc_REQ_PRESENT
#define  DNSc_REQ_PRESENT

/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#include  "dns-c.h"


/*
*********************************************************************************************************
*********************************************************************************************************
*                                         FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

void         DNScReq_ServerInit(const  DNSc_CFG       *p_cfg,
                                       DNSc_ERR       *p_err);

void         DNScReq_ServerSet (       DNSc_ADDR_OBJ  *p_addr,
                                       DNSc_ERR       *p_err);

void         DNScReq_ServerGet (       DNSc_ADDR_OBJ  *p_addr,
                                       DNSc_ERR       *p_err);

NET_SOCK_ID  DNScReq_Init      (       DNSc_ADDR_OBJ  *p_server_addr,
                                       NET_PORT_NBR    server_port,
                                       DNSc_ERR       *p_err);

NET_IF_NBR   DNSc_ReqIF_Sel    (       NET_IF_NBR      if_nbr_last,
                                       NET_SOCK_ID     sock_id,
                                       DNSc_ERR       *p_err);

void         DNSc_ReqClose     (       NET_SOCK_ID     sock_id);

CPU_INT16U   DNScReq_TxReq     (       CPU_CHAR       *p_host_name,
                                       NET_SOCK_ID     sock_id,
                                       CPU_INT16U      query_id,
                                       DNSc_REQ_TYPE   req_type,
                                       DNSc_ERR       *p_err);

DNSc_STATUS  DNScReq_RxResp    (const  DNSc_CFG       *p_cfg,
                                       DNSc_HOST_OBJ  *p_host,
                                       NET_SOCK_ID     sock_id,
                                       CPU_INT16U      query_id,
                                       DNSc_ERR       *p_err);

#endif  /* DNSc_REQ_PRESENT */
