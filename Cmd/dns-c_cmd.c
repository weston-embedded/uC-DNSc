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
*                                         uC/DNSc CMD MODULE
*
* Filename : dns-c_cmd.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) Assumes the following versions (or more recent) of software modules are included in
*                the project build :
*
*                (a) uC/DNSc   V2.00.00
*                (b) uC/TCP-IP V3.01.00
*                (c) uC/Shell  V1.03.01
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*********************************************************************************************************
*                                             INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#define  MICRIUM_SOURCE
#define  DNSc_CMD_MODULE


#include  "Source/dns-c.h"
#include  "dns-c_cmd.h"

#include  <Source/net_util.h>
#include  <Source/net_ascii.h>
#include  <Source/net_sock.h>

#include  <Cmd/net_cmd_output.h>

#include  <Source/shell.h>


/*
*********************************************************************************************************
*********************************************************************************************************
*                                           LOCAL CONSTANTS
*********************************************************************************************************
*********************************************************************************************************
*/

#define  DNSc_CMD_OUTPUT_ERR_REQ_FAIL          ("Request fail : ")
#define  DNSc_CMD_OUTPUT_ERR_STATUS_PENDING    ("Request is pending")
#define  DNSc_CMD_OUTPUT_ERR_STATUS_FAILED     ("Request failed")

#define  DNSc_CMD_OUTPUT_ERR_CLR_CACHE_FAIL    ("Cache clear failed : ")
#define  DNSc_CMD_OUTPUT_ERR_SET_SERVER_FAIL   ("Set server failed : ")


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

static  CPU_INT16S  DNScCmd_GetHost     (CPU_INT16U          argc,
                                         CPU_CHAR           *p_argv[],
                                         SHELL_OUT_FNCT      out_fnct,
                                         SHELL_CMD_PARAM    *p_cmd_param);

static  CPU_INT16S DNScCmd_SetServerAddr(CPU_INT16U          argc,
                                         CPU_CHAR           *p_argv[],
                                         SHELL_OUT_FNCT      out_fnct,
                                         SHELL_CMD_PARAM    *p_cmd_param);

static  CPU_INT16S DNScCmd_ClrCache     (CPU_INT16U          argc,
                                         CPU_CHAR           *p_argv[],
                                         SHELL_OUT_FNCT      out_fnct,
                                         SHELL_CMD_PARAM    *p_cmd_param);

static  CPU_INT16S  DNScCmd_Help        (CPU_INT16U          argc,
                                         CPU_CHAR           *p_argv[],
                                         SHELL_OUT_FNCT      out_fnct,
                                         SHELL_CMD_PARAM    *p_cmd_param);


/*
*********************************************************************************************************
*********************************************************************************************************
*                                            LOCAL TABLES
*********************************************************************************************************
*********************************************************************************************************
*/

static  SHELL_CMD DNSc_CmdTbl[] =
{
    {"dns_get_host",   DNScCmd_GetHost},
    {"dns_server_set", DNScCmd_SetServerAddr},
    {"dns_cache_clr",  DNScCmd_ClrCache},
    {"dns_help",       DNScCmd_Help},
    {0, 0 }
};


/*
*********************************************************************************************************
*                                           DNScCmd_Init()
*
* Description : Add <Network Application> test stubs to uC-Shell.
*
* Argument(s) : p_err    Pointer to variable that will receive the return error code from this function :
*
*                             DNSc_CMD_ERR_NONE         No error.
*                             DNSc_CMD_ERR_SHELL_INIT   Command table not added to uC-Shell
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScCmd_Init (DNSc_CMD_ERR  *p_err)
{
    SHELL_ERR  err;


    Shell_CmdTblAdd("dns", DNSc_CmdTbl, &err);
    if (err == SHELL_ERR_NONE) {
        *p_err = DNSc_CMD_ERR_NONE;
    } else {
        *p_err = DNSc_CMD_ERR_SHELL_INIT;
    }
}


/*
*********************************************************************************************************
*                                        DNScCmd_SetServerAddr()
*
* Description : Command to configure DNS client server to be used by default.
*
* Argument(s) : argc            is a count of the arguments supplied.
*
*               p_argv          an array of pointers to the strings which are those arguments.
*
*               out_fnct        is a callback to a respond to the requester.
*
*               p_cmd_param     is a pointer to additional information to pass to the command.
*
* Return(s)   : The number of positive data octets transmitted, if NO errors
*
*               SHELL_OUT_RTN_CODE_CONN_CLOSED,                 if implemented connection closed
*
*               SHELL_OUT_ERR,                                  otherwise
*
* Caller(s)   : Referenced in DNSc_CmdTbl.
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  CPU_INT16S  DNScCmd_SetServerAddr (CPU_INT16U          argc,
                                           CPU_CHAR           *p_argv[],
                                           SHELL_OUT_FNCT      out_fnct,
                                           SHELL_CMD_PARAM    *p_cmd_param)
{
    CPU_INT16S  output;
    DNSc_ERR    err;


    if (argc != 2) {
        output = NetCmd_OutputCmdArgInvalid(out_fnct, p_cmd_param);
        goto exit;
    }

    DNSc_CfgServerByStr(p_argv[1], &err);
    if (err != DNSc_ERR_NONE) {
        CPU_CHAR  msg[25];


        Str_Copy(msg, DNSc_CMD_OUTPUT_ERR_SET_SERVER_FAIL);
        Str_FmtNbr_Int32U(err, 5, 10, '\0', DEF_YES, DEF_YES, msg + sizeof(DNSc_CMD_OUTPUT_ERR_SET_SERVER_FAIL));
        output = NetCmd_OutputError(msg, out_fnct, p_cmd_param);
        goto exit;
    }

    output = NetCmd_OutputSuccess(out_fnct, p_cmd_param);

exit:
    return (output);
}

/*
*********************************************************************************************************
*                                           DNScCmd_GetHost()
*
* Description : Command to resolve an host name.
*
* Argument(s) : argc            is a count of the arguments supplied.
*
*               p_argv          an array of pointers to the strings which are those arguments.
*
*               out_fnct        is a callback to a respond to the requester.
*
*               p_cmd_param     is a pointer to additional information to pass to the command.
*
* Return(s)   : The number of positive data octets transmitted, if NO errors
*
*               SHELL_OUT_RTN_CODE_CONN_CLOSED,                 if implemented connection closed
*
*               SHELL_OUT_ERR,                                  otherwise
*
* Caller(s)   : Referenced in DNSc_CmdTbl.
*
* Note(s)     : None.
*********************************************************************************************************
*/

CPU_INT16S  DNScCmd_GetHost (CPU_INT16U        argc,
                             CPU_CHAR         *p_argv[],
                             SHELL_OUT_FNCT    out_fnct,
                             SHELL_CMD_PARAM  *p_cmd_param)
{
    DNSc_STATUS     status;
    DNSc_ADDR_OBJ   addrs[50];
    CPU_INT08U      addr_ctr = 50u;
    CPU_INT08U      ix;
    CPU_INT16S      output;
    DNSc_ERR        err;


    if (argc != 2) {
        output = NetCmd_OutputCmdArgInvalid(out_fnct, p_cmd_param);
        goto exit;
    }


    status = DNSc_GetHost(p_argv[1],
                          addrs,
                         &addr_ctr,
                          DNSc_FLAG_NONE,
                          DEF_NULL,
                         &err);
    if (err != DNSc_ERR_NONE) {
        CPU_CHAR  msg[20];


        Str_Copy(msg, DNSc_CMD_OUTPUT_ERR_REQ_FAIL);
        Str_FmtNbr_Int32U(err, 5, 10, '\0', DEF_YES, DEF_YES, msg + sizeof(DNSc_CMD_OUTPUT_ERR_REQ_FAIL));
        output = NetCmd_OutputError(msg, out_fnct, p_cmd_param);
        goto exit;
    }


    switch (status) {
        case DNSc_STATUS_RESOLVED:
             break;

        case DNSc_STATUS_PENDING:
             output = NetCmd_OutputError(DNSc_CMD_OUTPUT_ERR_STATUS_PENDING, out_fnct, p_cmd_param);
             goto exit;

        case DNSc_STATUS_FAILED:
        default:
             output = NetCmd_OutputError(DNSc_CMD_OUTPUT_ERR_STATUS_FAILED, out_fnct, p_cmd_param);
             goto exit;
    }

    for (ix = 0u; ix < addr_ctr; ix++) {
        CPU_CHAR  addr_str[NET_ASCII_LEN_MAX_ADDR_IP];
        NET_ERR   net_err;

        if (addrs[ix].Len == NET_IPv4_ADDR_LEN) {
#ifdef  NET_IPv4_MODULE_EN
            NET_IPv4_ADDR *p_addr = (NET_IPv4_ADDR *)addrs[ix].Addr;


            NetASCII_IPv4_to_Str(*p_addr, addr_str, NET_ASCII_LEN_MAX_ADDR_IP, &net_err);
#endif
        } else {
#ifdef  NET_IPv6_MODULE_EN
            NET_IPv6_ADDR *p_addr = (NET_IPv6_ADDR *)addrs[ix].Addr;


            NetASCII_IPv6_to_Str(p_addr, addr_str, DEF_NO, DEF_YES, &net_err);
#endif
        }

        output += NetCmd_OutputMsg(addr_str, DEF_YES, DEF_NO, DEF_YES, out_fnct, p_cmd_param);
    }

    output = NetCmd_OutputSuccess(out_fnct, p_cmd_param);

exit:
    return (output);
}


/*
*********************************************************************************************************
*                                          DNScCmd_ClrCache()
*
* Description : Command function to clear the cache.
*
* Argument(s) : argc            is a count of the arguments supplied.
*
*               p_argv          an array of pointers to the strings which are those arguments.
*
*               out_fnct        is a callback to a respond to the requester.
*
*               p_cmd_param     is a pointer to additional information to pass to the command.
*
* Return(s)   : The number of positive data octets transmitted, if NO errors
*
*               SHELL_OUT_RTN_CODE_CONN_CLOSED,                 if implemented connection closed
*
*               SHELL_OUT_ERR,                                  otherwise
*
* Caller(s)   : Referenced in DNSc_CmdTbl.
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  CPU_INT16S  DNScCmd_ClrCache (CPU_INT16U        argc,
                                      CPU_CHAR         *p_argv[],
                                      SHELL_OUT_FNCT    out_fnct,
                                      SHELL_CMD_PARAM  *p_cmd_param)
{
    CPU_INT16S output;
    DNSc_ERR   err;


    if (argc != 1) {
        output = NetCmd_OutputCmdArgInvalid(out_fnct, p_cmd_param);
        goto exit;
    }

    DNSc_CacheClrAll(&err);
    if (err != DNSc_ERR_NONE) {
        CPU_CHAR  msg[25];


        Str_Copy(msg, DNSc_CMD_OUTPUT_ERR_CLR_CACHE_FAIL);
        Str_FmtNbr_Int32U(err, 5, 10, '\0', DEF_YES, DEF_YES, msg + sizeof(DNSc_CMD_OUTPUT_ERR_CLR_CACHE_FAIL));
        output = NetCmd_OutputError(msg, out_fnct, p_cmd_param);
        goto exit;
    }

    output = NetCmd_OutputSuccess(out_fnct, p_cmd_param);

exit:
    return (output);
}


/*
*********************************************************************************************************
*                                            DNScCmd_Help()
*
* Description : Output DNSc command help.
*
* Argument(s) : argc            is a count of the arguments supplied.
*
*               p_argv          an array of pointers to the strings which are those arguments.
*
*               out_fnct        is a callback to a respond to the requester.
*
*               p_cmd_param     is a pointer to additional information to pass to the command.
*
* Return(s)   : The number of positive data octets transmitted, if NO errors
*
*               SHELL_OUT_RTN_CODE_CONN_CLOSED,                 if implemented connection closed
*
*               SHELL_OUT_ERR,                                  otherwise
*
* Caller(s)   : Referenced in DNSc_CmdTbl.
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  CPU_INT16S DNScCmd_Help (CPU_INT16U        argc,
                                 CPU_CHAR         *p_argv[],
                                 SHELL_OUT_FNCT    out_fnct,
                                 SHELL_CMD_PARAM  *p_cmd_param)
{
    CPU_INT16S  ret_val;


    ret_val = NetCmd_OutputCmdTbl(DNSc_CmdTbl, out_fnct, p_cmd_param);

    return (ret_val);
}

