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
*                                     DNS CLIENT TYPE DEFINITION
*
* Filename : dns-c_type.h
* Version  : V2.02.00
*********************************************************************************************************
*/

#ifndef DNSc_TYPE_PRESENT
#define DNSc_TYPE_PRESENT

#include  <cpu.h>
#include  <lib_def.h>
#include  <lib_mem.h>


/*
*********************************************************************************************************
*********************************************************************************************************
*                                           DNS CFG DATA TYPES
*********************************************************************************************************
*********************************************************************************************************
*/

typedef  struct  DNSc_cfg_task {
    CPU_INT32U  Prio;
    CPU_INT16U  StkSizeBytes;
    CPU_ADDR    StkPtr;
} DNSc_CFG_TASK;


typedef  struct DNSc_cfg {
    MEM_SEG        *MemSegPtr;

    CPU_CHAR       *ServerDfltPtr;
    CPU_INT16U      HostNameLenMax;

    CPU_INT08U      CacheEntriesMaxNbr;

    CPU_INT08U      AddrIPv4MaxPerHost;
    CPU_INT08U      AddrIPv6MaxPerHost;

    CPU_INT08U      TaskDly_ms;
    CPU_INT08U      ReqRetryNbrMax;
    CPU_INT16U      ReqRetryTimeout_ms;
} DNSc_CFG;


#endif

