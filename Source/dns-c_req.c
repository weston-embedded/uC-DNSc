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
* Filename : dns-c_req.c
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

#define  MICRIUM_SOURCE
#define  DNSc_REQ_MODULE



/*
*********************************************************************************************************
*********************************************************************************************************
*                                            INCLUDE FILES
*********************************************************************************************************
*********************************************************************************************************
*/

#include  <cpu.h>
#include  <lib_def.h>

#include  "dns-c_req.h"
#include  "dns-c_cache.h"

#include  <Source/net_cfg_net.h>

#ifdef  NET_IPv4_MODULE_EN
#include  <IP/IPv4/net_ipv4.h>
#endif
#ifdef  NET_IPv6_MODULE_EN
#include  <IP/IPv6/net_ipv6.h>
#endif

#include  <Source/net_ascii.h>
#include  <Source/net_util.h>
#include  <Source/net_app.h>


/*
*********************************************************************************************************
*********************************************************************************************************
*                                               DEFINES
*********************************************************************************************************
*********************************************************************************************************
*/


/*
*********************************************************************************************************
*                                  DNS MODULE CONFIGURATION DEFINES
*********************************************************************************************************
*/

#define  DNSc_PKT_MAX_SIZE                               512u
#define  DNSc_PKT_HDR_SIZE                                12u
#define  DNSc_PKT_TYPE_SIZE                                2u
#define  DNSc_PKT_CLASS_SIZE                               2u
#define  DNSc_PKT_TTL_SIZE                                 4u

#define  DNSc_HDR_MSG_LEN_MAX       (DNSc_PKT_MAX_SIZE - DNSc_PKT_HDR_SIZE)

#define  DNSc_NAME_LEN_SIZE                                1u
#define  DNSc_ZERO_CHAR_SIZE                               1u

#define  DNSc_MAX_RX_RETRY                                 3u
#define  DNSc_MAX_RX_DLY_MS                              100u

#define  DNSc_SOCK_TX_RETRY_MAX                            5u
#define  DNSc_SOCK_TX_DLY_MS                              10u

/*
*********************************************************************************************************
*                                           DNS TYPE DEFINE
*
* Note(s) : (1) Fixed value of the the DNS hdr.
*
*               (a) Outgoing DNS msg might contain only one question and should not contain any answer
*                   record, authority record or additional info.
*
*               (b) Value of param is fixed so that DNS outgoing pkt represent a standard query and that
*                   recursion is desired.
*
*           (2) Message compression format is described in RFC #1035, Section 4.1.4.
*
*               (a) The returned host name may be whether a literal string in the format of a 1-byte count
*                   followed by the characters that make up the name,or a pointer to a literal string. In
*                   the case of a compressed host name, the pointer can be represented as follows :
*
*                         1  1  1  1  1  1
*                         5  4  3  2  1  0  9  8  7  6  5  4  3  2  1  0
*                       -------------------------------------------------
*                       | 1| 1|                 OFFSET                  |
*                       -------------------------------------------------
*
*                   where OFFSET specifies an offset from the first byte of the ID field in the domain
*                   header. To reach the IP addr, we must skip over the returned host name, whether it
*                   is compressed or not. To detect a compression, the 6 LSB of the first byte must be
*                   masked.
*
*               (b) If the host name is compressed, the pkt pointer should skip over the pointer that
*                   refers to the literal host name string, which has size of 2 bytes.
*
*
**********************************************************************************************************
*/

                                                                /* See Note #1a.                                        */
#define  DNSc_QUESTION_NBR                                 1u
#define  DNSc_ANSWER_NBR                                   0u
#define  DNSc_AUTHORITY_NBR                                0u
#define  DNSc_ADDITIONAL_NBR                               0u

#define  DNSc_PARAM_ENTRY                             0x0100    /* See Note #1b.                                        */

#define  DNSc_TYPE_A                                       1u   /* Host      addr type (see RFC #1035, Section 3.2.2).  */
#define  DNSc_TYPE_CNAME                                   5u   /* Canonical addr type (see RFC #1035, Section 3.3.1).  */
#define  DNSc_TYPE_AAAA                                   28u   /* Host      addr type (see RFC #3596, Section 2.1).    */
#define  DNSc_CLASS_IN                                     1u   /* Internet class      (see RFC #1035, Section 3.2.4).  */
#define  DNSc_TYPE_PTR                                    12u   /* Pointer type.                                        */

#define  DNSc_PARAM_QUERY                                  0u   /* Query operation     (see RFC #1035, Section 4.1.1).  */


#define  DNSc_PARAM_MASK_QR                           0x8000    /* Mask the 15 MSBs to extract the operation type.      */
#define  DNSc_PARAM_MASK_RCODE                        0x000F    /* Mask the 12 LSBs to extract the response code.       */

#define  DNSc_ANSWER_NBR_MIN                               1u   /* Response msg should contain at least one answer.     */

#define  DNSc_COMP_ANSWER                               0xC0    /* See Note #2a.                                        */
#define  DNSc_HOST_NAME_PTR_SIZE                           2u   /* See Note #2b.                                        */


#define  DNSc_RCODE_NO_ERR                                 0u   /* No error code       (see RFC #1035, Section 4.1.1).  */
#define  DNSc_RCODE_INVALID_REQ_FMT                        1u
#define  DNSc_RCODE_SERVER_FAIL                            2u
#define  DNSc_RCODE_NAME_NOT_EXIST                         3u


#define  DNSc_PORT_DFLT                                   53u   /* Configure client IP port. Default is 53.             */


/*
*********************************************************************************************************
*********************************************************************************************************
*                                              DATA TYPES
*********************************************************************************************************
*********************************************************************************************************
*/

typedef  struct  DNSc_server {
    DNSc_ADDR_OBJ  Addr;
    CPU_BOOLEAN    IsValid;
} DNSc_SERVER;


/*
*********************************************************************************************************
*                                          DNS MSG DATA TYPE
*
* Note(s) : (1) See RFC #1035, section 4.1 for DNS message format.
*
*           (2) Param is a 16 bits field that specifies the operation requested and a response code that
*               can be represented as follows :
*
*                         1  1  1  1  1  1
*                         5  4  3  2  1  0  9  8  7  6  5  4  3  2  1  0
*                       -------------------------------------------------
*                       |   RCODE   |   RSV  |RA|RD|TC|AA|   QTYPE   |QR|
*                       -------------------------------------------------
*
*                   where
*                           RCODE        Response code
*                                        0    No error
*                                        1    Format error in query
*                                        2    Server failure
*                                        3    Name does not exist
*                                        4    Query not supported by server
*                                        5    Query refused by server
*
*                           RSV          Reserved

*                           RA           Set if recursion available
*                           RD           Set if recursion desired
*                           TC           Set if message truncated
*                           AA           Set if answer authoritative
*
*                           QTYPE        Query type
*                                        0    Standard
*                                        1    Inverse
*                                        2    Obsolete
*                                        3    Obsolete
*
*                           QR           Operation type
*                                        0    Query
*                                        1    Response
*********************************************************************************************************
*/

typedef  struct  DNSc_Msg {
    CPU_INT16U   QueryID;                                       /* Unique ID.                                           */
    CPU_INT16U   Param;                                         /* Parameters (see Note #2).                            */
    CPU_INT16U   QuestionNbr;                                   /* Number of question records.                          */
    CPU_INT16U   AnswerNbr;                                     /* Number of answer records.                            */
    CPU_INT16U   AuthorityNbr;                                  /* Number of authoritative name server records.         */
    CPU_INT16U   AdditionalNbr;                                 /* Number of additional info.                           */
    CPU_INT08U   QueryMsg;
} DNSc_HDR;


typedef  struct  DNSc_query_info {
    CPU_INT16U  Type;
    CPU_INT16U  Class;

} DNSc_QUERY_INFO;


/*
*********************************************************************************************************
*********************************************************************************************************
*                                       LOCAL GLOBAL VARIABLES
*********************************************************************************************************
*********************************************************************************************************
*/

static  CPU_INT16U   DNSc_QueryID = 1u;
static  DNSc_SERVER  DNSc_ServerAddr;


/*
*********************************************************************************************************
*********************************************************************************************************
*                                      LOCAL FUNCTION PROTOTYPES
*********************************************************************************************************
*********************************************************************************************************
*/

static  CPU_INT16U  DNScReq_TxPrepareMsg (       CPU_INT08U     *p_buf,
                                                 CPU_INT16U      buf_len,
                                                 CPU_CHAR       *p_host_name,
                                                 DNSc_REQ_TYPE   req_type,
                                                 CPU_INT16U      req_query_id,
                                                 DNSc_ERR       *p_err);

static  void        DNScReq_RxRespMsg    (const  DNSc_CFG       *p_cfg,
                                                 DNSc_HOST_OBJ  *p_host,
                                                 CPU_INT08U     *p_resp_msg,
                                                 CPU_INT16U      resp_msg_len,
                                                 CPU_INT16U      req_query_id,

                                                 DNSc_ERR       *p_err);

static  void        DNScReq_RxRespAddAddr(const  DNSc_CFG       *p_cfg,
                                                 DNSc_HOST_OBJ  *p_host,
                                                 CPU_INT16U      answer_type,
                                                 CPU_INT08U     *p_data,
                                                 CPU_INT08U     *p_resp_msg,
                                                 CPU_INT16U      answer_size,
                                                 DNSc_ERR       *p_err);

static  void        DNScReq_TxData       (       NET_SOCK_ID     sock_id,
                                                 CPU_INT08U     *p_buf,
                                                 CPU_INT16U      data_len,
                                                 DNSc_ERR       *p_err);

static  CPU_INT16U  DNScReq_RxData       (       NET_SOCK_ID     sock_id,
                                                 CPU_INT08U     *p_buf,
                                                 CPU_INT16U      buf_len,
                                                 DNSc_ERR       *p_err);


/*
*********************************************************************************************************
*                                           DNSc_ServerInit()
*
* Description : Initialize default request server.
*
* Argument(s) : p_cfg   Pointer to the DNS'c configuration.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Request server successfully initialized.
*                           DNSc_ERR_INVALID_CFG    Invalid server configuration.
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

void  DNScReq_ServerInit (const  DNSc_CFG  *p_cfg,
                                 DNSc_ERR  *p_err)
{
    DNSc_SERVER  server_addr;
    CPU_SR_ALLOC();



    if (p_cfg->ServerDfltPtr != DEF_NULL) {
        DNScCache_AddrObjSet(&server_addr.Addr, p_cfg->ServerDfltPtr, p_err);
        if (*p_err != DNSc_ERR_NONE) {
            *p_err  = DNSc_ERR_INVALID_CFG;
             goto exit;
        }

        server_addr.IsValid = DEF_YES;

    } else {
        server_addr.IsValid = DEF_NO;
    }

    CPU_CRITICAL_ENTER();
    DNSc_ServerAddr = server_addr;
    CPU_CRITICAL_EXIT();

   *p_err = DNSc_ERR_NONE;


exit:
    return;
}


/*
*********************************************************************************************************
*                                          DNScReq_ServerSet()
*
* Description : Set server's address.
*
* Argument(s) : p_addr  Pointer to IP address.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Server address successfully Set.
*
* Return(s)   : None.
*
* Caller(s)   : DNSc_CfgServerByAddr(),
*               DNSc_CfgServerByStr().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScReq_ServerSet (DNSc_ADDR_OBJ  *p_addr,
                         DNSc_ERR       *p_err)
{
    CPU_SR_ALLOC();


    CPU_CRITICAL_ENTER();
    DNSc_ServerAddr.Addr    = *p_addr;
    DNSc_ServerAddr.IsValid =  DEF_YES;
    CPU_CRITICAL_EXIT();

   *p_err = DNSc_ERR_NONE;
}


/*
*********************************************************************************************************
*                                          DNScReq_ServerGet()
*
* Description : Get the server's address configured.
*
* Argument(s) : p_addr  Pointer to structure that will receive the IP address of the DNS server.
*
*               p_err   Pointer to variable that will receive the return error code from this function :
*
*                           DNSc_ERR_NONE           Successfully returned.
*                           DNSc_ERR_ADDR_INVALID   Invalid server's address.
*
* Return(s)   : None.
*
* Caller(s)   : DNSc_GetServerByAddr(),
*               DNSc_GetServerByStr().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNScReq_ServerGet (DNSc_ADDR_OBJ  *p_addr,
                         DNSc_ERR       *p_err)
{
    CPU_BOOLEAN  valid = DEF_NO;
    DNSc_SERVER  server_addr;
    CPU_SR_ALLOC();


    CPU_CRITICAL_ENTER();
    server_addr = DNSc_ServerAddr;
    CPU_CRITICAL_EXIT();


    valid = server_addr.IsValid;
    if (valid == DEF_YES) {
       *p_addr = server_addr.Addr;
    }

    if (valid != DEF_YES) {
       *p_err = DNSc_ERR_ADDR_INVALID;
        goto exit;
    }

   *p_err =  DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                            DNScReq_Init()
*
* Description : Initialize request.
*
* Argument(s) : p_server_addr   Pointer to the server address to use for the request.
*
*               server_port     Server port.
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE               Successfully initialized.
*                                   DNSc_ERR_INVALID_SERVER     Invalid server address.
*                                   DNSc_ERR_ADDR_INVALID       Invalid IP address.
*                                   DNSc_ERR_SOCK_OPEN_FAIL     Failed to initialize a socket.
*
*
* Return(s)   : Socket ID,        if successfully initialized.
*
*               NET_SOCK_ID_NONE, otherwise.
*
* Caller(s)   : DNScCache_Resolve().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

NET_SOCK_ID  DNScReq_Init (DNSc_ADDR_OBJ  *p_server_addr,
                           NET_PORT_NBR    server_port,
                           DNSc_ERR       *p_err)
{
#ifdef  NET_IPv4_MODULE_EN
    NET_IPv4_ADDR              net_ipv4_addr_any;
#endif
    DNSc_ADDR_OBJ             *p_server;
    NET_SOCK_ADDR_FAMILY       addr_family;
    NET_SOCK_PROTOCOL_FAMILY   protocol_family;
    NET_SOCK_ID                sock_id = NET_SOCK_ID_NONE;
    NET_PORT_NBR               port    = DNSc_PORT_DFLT;
    NET_SOCK_ADDR              sock_addr_server;
    NET_SOCK_ADDR              sock_addr_local;
    NET_SOCK_ADDR_LEN          addr_len;
    CPU_INT08U                *p_addr;
    NET_ERR                    net_err;
    DNSc_SERVER                server_addr;
    CPU_SR_ALLOC();


    CPU_CRITICAL_ENTER();
    server_addr = DNSc_ServerAddr;
    CPU_CRITICAL_EXIT();

    if (p_server_addr == DEF_NULL) {

        if (server_addr.IsValid == DEF_NO) {
           *p_err = DNSc_ERR_INVALID_SERVER;
            goto exit_sock_id_none;
        }

        p_server = &server_addr.Addr;

    } else {
        p_server =  p_server_addr;
    }

    if (server_port != NET_PORT_NBR_NONE) {
        port = server_port;
    }


    switch (p_server->Len) {
#ifdef  NET_IPv4_MODULE_EN
        case NET_IPv4_ADDR_LEN:
             addr_family       = NET_SOCK_ADDR_FAMILY_IP_V4;
             protocol_family   = NET_SOCK_PROTOCOL_FAMILY_IP_V4;
             net_ipv4_addr_any =  NET_IPv4_ADDR_ANY;
             p_addr            = (CPU_INT08U *)&net_ipv4_addr_any;
             addr_len          =  NET_IPv4_ADDR_SIZE;
             break;
#endif

#ifdef  NET_IPv6_MODULE_EN
        case NET_IPv6_ADDR_LEN:
             addr_family     = NET_SOCK_ADDR_FAMILY_IP_V6;
             protocol_family = NET_SOCK_PROTOCOL_FAMILY_IP_V6;
             p_addr          = (CPU_INT08U *)&NET_IPv6_ADDR_ANY;
             addr_len        =  NET_IPv6_ADDR_SIZE;
             break;
#endif

        case NET_IP_ADDR_FAMILY_UNKNOWN:
        default:
            *p_err = DNSc_ERR_ADDR_INVALID;
             goto exit_sock_id_none;
    }



                                                                /* --- CREATE SOCKET TO COMMUNICATE WITH DNS SERVER --- */
    sock_id = NetSock_Open(protocol_family,
                           NET_SOCK_TYPE_DATAGRAM,
                           NET_SOCK_PROTOCOL_UDP,
                          &net_err);
    if (net_err != NET_SOCK_ERR_NONE) {
        *p_err = DNSc_ERR_SOCK_OPEN_FAIL;
         goto exit_sock_id_none;
    }


    NetApp_SetSockAddr(&sock_addr_local,
                        addr_family,
                        NET_PORT_NBR_NONE,
                        p_addr,
                        addr_len,
                       &net_err);
    if (net_err != NET_APP_ERR_NONE) {
       *p_err = DNSc_ERR_SOCK_OPEN_FAIL;
        goto exit_close_sock;
    }


    NetApp_SetSockAddr(&sock_addr_server,
                        addr_family,
                        port,
                        p_server->Addr,
                        p_server->Len,
                       &net_err);
    if (net_err != NET_APP_ERR_NONE) {
       *p_err = DNSc_ERR_SOCK_OPEN_FAIL;
        goto exit_close_sock;
    }


    (void)NetSock_Bind(sock_id,
                      &sock_addr_local,
                       sizeof(sock_addr_local),
                      &net_err);
    if (net_err != NET_SOCK_ERR_NONE) {
       *p_err = DNSc_ERR_SOCK_OPEN_FAIL;
        goto exit_close_sock;
    }

    NetSock_Conn(sock_id,                                       /* Open sock to DNS server.                             */
                &sock_addr_server,
                 sizeof(sock_addr_server),
                &net_err);
    if (net_err != NET_SOCK_ERR_NONE) {
       *p_err = DNSc_ERR_SOCK_OPEN_FAIL;
        goto exit_close_sock;
    }

   *p_err = DNSc_ERR_NONE;


    goto exit;

exit_close_sock:
    NetSock_Close(sock_id,
                 &net_err);

exit_sock_id_none:
    sock_id = NET_SOCK_ID_NONE;

exit:
    return (sock_id);
}


/*
*********************************************************************************************************
*                                            DNSc_ReqIF_Sel()
*
* Description : Choose an interface through which a DNS request will be sent.
*
* Argument(s) : if_nbr_last  Last configured interface number.
*
*               sock_id      Socket ID used for the request.
*
*               p_err        Pointer to variable that will receive the return error code from this function :
*
*                                DNSc_ERR_NONE            Request successfully completed.
*                                DNSc_ERR_IF_LINK_DOWN    None of the configured interfaces have an active link.
*                                DNSc_ERR_NO_RESPONSE     Interface number is invalid.
*                                DNSc_ERR_SOCK_OPEN_FAIL  Socket could not be cfg'd to communicate through
*                                                         an interface.
*
* Return(s)   : The interface number selected for the outgoing request.
*
* Caller(s)   : DNScCache_Resolve().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

NET_IF_NBR  DNSc_ReqIF_Sel (NET_IF_NBR   if_nbr_last,
                            NET_SOCK_ID  sock_id,
                            DNSc_ERR    *p_err)
{
    NET_IF_NBR  if_nbr_up = NET_IF_NBR_NONE;
    NET_IF_NBR  if_nbr_ix;
    NET_IF_NBR  if_nbr_cfgd;
    NET_IF_NBR  if_nbr_base;
    NET_ERR     net_err;


    if_nbr_base  = NetIF_GetNbrBaseCfgd();
    if_nbr_cfgd  = NetIF_GetExtAvailCtr(&net_err);
    if_nbr_cfgd -= if_nbr_base;

    if (if_nbr_last != NET_IF_NBR_WILDCARD) {
        if_nbr_ix = if_nbr_last + 1;
        if (if_nbr_ix > if_nbr_cfgd) {
           *p_err = DNSc_ERR_NO_RESPONSE;
            goto exit;
        }

    } else {
        if_nbr_ix = if_nbr_base;
    }


    for (; if_nbr_ix <= if_nbr_cfgd; if_nbr_ix++) {
        NET_IF_LINK_STATE  state  = NET_IF_LINK_DOWN;

        state = NetIF_LinkStateGet(if_nbr_ix, &net_err);
        if ((state == NET_IF_LINK_UP) &&
            (if_nbr_up == NET_IF_NBR_NONE)) {
            if_nbr_up = if_nbr_ix;
            break;
        }
    }


    if (if_nbr_up == NET_IF_NBR_NONE) {
       *p_err = DNSc_ERR_IF_LINK_DOWN;
        goto exit;
    }


    NetSock_CfgIF(sock_id, if_nbr_up, &net_err);
    if (net_err != NET_SOCK_ERR_NONE) {
        *p_err = DNSc_ERR_SOCK_OPEN_FAIL;
         goto exit;
    }

   *p_err = DNSc_ERR_NONE;

exit:
    return (if_nbr_up);
}


/*
*********************************************************************************************************
*                                            DNSc_ReqClose()
*
* Description : Close request objects.
*
* Argument(s) : sock_id     Socket ID used during the request.
*
* Return(s)   : None.
*
* Caller(s)   : DNScCache_Resolve().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

void  DNSc_ReqClose (NET_SOCK_ID  sock_id)
{
    NET_ERR err;


    NetSock_Close(sock_id, &err);
}


/*
*********************************************************************************************************
*                                            DNScReq_TxReq()
*
* Description : Prepare request and transmit to the server.
*
* Argument(s) : p_host_name     Pointer to a string that contains the host name to resolve.
*
*               sock_id         Socket ID.
*
*               query_id        Query ID of the request.
*
*                                   DNSc_QUERY_ID_NONE a new query ID is generated.
*
*               req_type        Request type:
*
*                                   DNSc_REQ_TYPE_IPv4  Request IPv4 address(es)
*                                   DNSc_REQ_TYPE_IPv6  Request IPv6 address(es)
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE  Request successfully completed.
*
*                               RETURNED BY DNScReq_TxReqPrepare():
*                                   See DNScReq_TxReqPrepare() for additional return error codes.
*
*                               RETURNED BY DNScReq_TxData():
*                                   See DNScReq_TxData() for additional return error codes.
*
* Return(s)   : Query ID, if successfully transmitted.
*
*               DNSc_QUERY_ID_NONE, Otherwise.
*
* Caller(s)   : DNScCache_Req().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

CPU_INT16U  DNScReq_TxReq (CPU_CHAR       *p_host_name,
                           NET_SOCK_ID     sock_id,
                           CPU_INT16U      query_id,
                           DNSc_REQ_TYPE   req_type,
                           DNSc_ERR       *p_err)
{
    CPU_INT08U  buf[DNSc_PKT_MAX_SIZE];
    CPU_INT16U  req_query_id = DNSc_QUERY_ID_NONE;
    CPU_INT16U  data_len;



    if (query_id == DNSc_QUERY_ID_NONE) {
        CPU_SR_ALLOC();

        CPU_CRITICAL_ENTER();
        req_query_id = DNSc_QueryID++;
        CPU_CRITICAL_EXIT();
    }

    data_len = DNScReq_TxPrepareMsg(buf, DNSc_PKT_MAX_SIZE, p_host_name, req_type, req_query_id, p_err);
    if (*p_err != DNSc_ERR_NONE) {
        goto exit_err;
    }

    DNScReq_TxData(sock_id, buf, data_len, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit_err;
    }


   *p_err = DNSc_ERR_NONE;

    goto exit;


exit_err:

    req_query_id = DNSc_QUERY_ID_NONE;

exit:
    return (req_query_id);
}


/*
*********************************************************************************************************
*                                           DNScReq_RxResp()
*
* Description : Receive DNS response.
*
* Argument(s) : p_cfg       Pointer to DNSc's configuration.
*
*               p_host      Pointer to the host object.
*
*               sock_id     Socket ID.
*
*               query_id    Query ID of the request.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE   Response received and host resolved.
*
*                               RETURNED BY DNScReq_RxData():
*                                   See DNScReq_RxData() for additional return error codes.
*
*                               RETURNED BY DNScReq_RxRespProcess():
*                                   See DNScReq_RxRespProcess() for additional return error codes.
*
* Return(s)   : Request Status:
*
*                   DNSc_STATUS_PENDING
*                   DNSc_STATUS_RESOLVED
*
* Caller(s)   : DNScCache_Resp().
*
* Note(s)     : None.
*********************************************************************************************************
*/

DNSc_STATUS  DNScReq_RxResp (const  DNSc_CFG       *p_cfg,
                                    DNSc_HOST_OBJ  *p_host,
                                    NET_SOCK_ID     sock_id,
                                    CPU_INT16U      query_id,
                                    DNSc_ERR       *p_err)
{

    DNSc_STATUS  status = DNSc_STATUS_PENDING;
    CPU_INT08U   buf[DNSc_PKT_MAX_SIZE];
    CPU_INT16U   data_len;


    data_len = DNScReq_RxData(sock_id, buf, sizeof(buf), p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }

    DNScReq_RxRespMsg(p_cfg, p_host, buf, data_len, query_id, p_err);
    if (*p_err != DNSc_ERR_NONE) {
         goto exit;
    }

    status = DNSc_STATUS_RESOLVED;

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
*                                        DNScReq_TxPrepareMsg()
*
* Description : Prepare request's message.
*
* Argument(s) : p_buf           Buffer where to format the request.
*
*               buf_len         Request's buffer length.
*
*               p_host_name     Pointer to a string that contains the host name to resolve.
*
*               req_type        Request type:
*
*                                   DNSc_REQ_TYPE_IPv4  Request IPv4 address(es)
*                                   DNSc_REQ_TYPE_IPv6  Request IPv6 address(es)
*
*               req_query_id    Request ID.
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE               Request sucessfully prepared.
*                                   DNSc_ERR_INVALID_HOST_NAME  Invalid host name.
*                                   DNSc_ERR_FAULT              Unknown error.
*
* Return(s)   : Message length.
*
* Caller(s)   : DNScReq_TxReq().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  CPU_INT16U  DNScReq_TxPrepareMsg (CPU_INT08U     *p_buf,
                                          CPU_INT16U      buf_len,
                                          CPU_CHAR       *p_host_name,
                                          DNSc_REQ_TYPE   req_type,
                                          CPU_INT16U      req_query_id,
                                          DNSc_ERR       *p_err)
{
    DNSc_HDR    *p_hdr       = (DNSc_HDR *)p_buf;
    CPU_INT08U  *p_query;
    CPU_INT08U  *p_cname;
    CPU_INT16U   msg_len     =  0u;
    CPU_INT16U   msg_type;
    CPU_INT16U   buf_rem_len = buf_len;
    CPU_INT16U   dns_class;
    CPU_CHAR    *p_name;
    CPU_CHAR    *p_dot;


    switch (req_type) {
        case DNSc_REQ_TYPE_IPv4:
             msg_type = DNSc_TYPE_A;
             break;

        case DNSc_REQ_TYPE_IPv6:
             msg_type = DNSc_TYPE_AAAA;
             break;

        case DNSc_REQ_TYPE_PTR_IPv4:
        case DNSc_REQ_TYPE_PTR_IPv6:
             msg_type = DNSc_TYPE_PTR;
             break;

        default:
            *p_err = DNSc_ERR_FAULT;
             goto exit;
    }


    p_hdr->QueryID       = NET_UTIL_HOST_TO_NET_16(req_query_id);
    p_hdr->Param         = NET_UTIL_HOST_TO_NET_16(DNSc_PARAM_ENTRY);
    p_hdr->QuestionNbr   = NET_UTIL_HOST_TO_NET_16(DNSc_QUESTION_NBR);
    p_hdr->AnswerNbr     = NET_UTIL_HOST_TO_NET_16(DNSc_ANSWER_NBR);
    p_hdr->AuthorityNbr  = NET_UTIL_HOST_TO_NET_16(DNSc_AUTHORITY_NBR);
    p_hdr->AdditionalNbr = NET_UTIL_HOST_TO_NET_16(DNSc_ADDITIONAL_NBR);



    p_query      = &p_hdr->QueryMsg;
    p_cname      =  p_query;
    buf_rem_len -= (p_query - p_buf);
    p_name       =  p_host_name;

    do {                                                        /* Message compression (See RFC-1035 Section 4.1.4)     */
        CPU_INT08U  str_len;


        p_dot = Str_Char(p_name, ASCII_CHAR_FULL_STOP);
        if (p_dot != DEF_NULL) {
            str_len = p_dot - p_name;                           /* Nb of chars between char and next '.'                */

        } else {
            str_len = Str_Len_N(p_name, buf_len);               /* Nb of chars between first char and '\0'              */
        }


        if ((str_len <= 0u)          &&
            (str_len >  buf_rem_len)) {
           *p_err = DNSc_ERR_INVALID_HOST_NAME;
            goto exit;
        }

       *p_cname = str_len;                                     /* Put number of char that follow before the next stop. */
        p_cname++;

        Mem_Copy(p_cname, p_name, str_len);                    /* Copy Chars                                           */

        p_name       = (p_dot   + 1u);
        p_cname     +=  str_len;
        buf_rem_len -=  str_len;
    } while (p_dot);


   *p_cname = ASCII_CHAR_NULL;                                  /* Insert end of line char                              */
    p_cname++;

    p_query  = p_cname;

    msg_type = NET_UTIL_HOST_TO_NET_16(msg_type);               /* Set query TYPE.                                      */
    Mem_Copy(p_query, &msg_type, sizeof(msg_type));


    p_query += sizeof(msg_type);

    dns_class = NET_UTIL_HOST_TO_NET_16(DNSc_CLASS_IN);         /* Set query CLASS.                                     */
    Mem_Copy(p_query, &dns_class, sizeof(dns_class));
    p_query += sizeof(dns_class);

    msg_len  = p_query - p_buf;                                 /* Compute total pkt size (see Note #4).                */


   *p_err = DNSc_ERR_NONE;

exit:
    return (msg_len);
}


/*
*********************************************************************************************************
*                                          DNScReq_RxRespMsg()
*
* Description : Analyze response message.
*
* Argument(s) : p_cfg           Pointer to DNSc's configuration.
*
*               p_resp_msg      Pointer to the response's message.
*
*               resp_msg_len    Response's message length
*
*               req_query_id    Request ID expected.
*
*               p_host          Pointer to a host object.
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE                   Response successfully parsed.
*                                   DNSc_ERR_NOT_A_RESPONSE         Invalid message type.
*                                   DNSc_ERR_BAD_RESPONSE_ID        Invalid response ID.
*                                   DNSc_ERR_FMT                    Bad formating.
*                                   DNSc_ERR_SERVER_FAIL            Server return fail error.
*                                   DNSc_ERR_NAME_NOT_EXIST         Server didn't find the host name.
*                                   DNSc_ERR_BAD_RESPONSE_TYPE      Invalid response type.
*                                   DNSc_ERR_BAD_QUESTION_COUNT     Invalid question count.
*
*
* Return(s)   : none.
*
* Caller(s)   : DNScReq_RxResp().
*
*               This function is an INTERNAL function & MUST NOT be called by application function(s).
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScReq_RxRespMsg (const  DNSc_CFG       *p_cfg,
                                        DNSc_HOST_OBJ  *p_host,
                                        CPU_INT08U     *p_resp_msg,
                                        CPU_INT16U      resp_msg_len,
                                        CPU_INT16U      req_query_id,
                                        DNSc_ERR       *p_err)
{
    DNSc_HDR    *p_dns_msg = (DNSc_HDR *)p_resp_msg;
    CPU_INT16U   query_id;
    CPU_INT16U   question_nbr;
    CPU_INT16U   answer_nbr;
    CPU_INT08U  *p_data;
    CPU_INT16U   answer_type;
    CPU_INT16U   data_16;
    CPU_INT08U   ix;


    Mem_Copy(&data_16, &p_dns_msg->Param, sizeof(p_dns_msg->Param));
    data_16 = NET_UTIL_NET_TO_HOST_16(data_16) & DNSc_PARAM_MASK_QR;
    if (data_16 == DNSc_PARAM_QUERY) {                          /* If the response is not a query response,         ... */
       *p_err = DNSc_ERR_NOT_A_RESPONSE;                        /* ... rtn err.                                         */
        return;
    }


    Mem_Copy(&query_id, &p_dns_msg->QueryID, sizeof(p_dns_msg->QueryID));
    query_id= NET_UTIL_NET_TO_HOST_16(query_id);                /* If the query ID is incorrect,                    ... */
    if (query_id != req_query_id) {
       *p_err = DNSc_ERR_BAD_RESPONSE_ID;                       /* ... rtn err.                                         */
        return;
    }

    Mem_Copy(&data_16, &p_dns_msg->Param, sizeof(p_dns_msg->Param));
    data_16 = NET_UTIL_NET_TO_HOST_16(data_16) & DNSc_PARAM_MASK_RCODE;
    switch (data_16) {
        case DNSc_RCODE_NO_ERR:
             break;

        case DNSc_RCODE_INVALID_REQ_FMT:
            *p_err = DNSc_ERR_FMT;
             goto exit;

        case DNSc_RCODE_SERVER_FAIL:
            *p_err = DNSc_ERR_SERVER_FAIL;
             goto exit;

        case DNSc_RCODE_NAME_NOT_EXIST:
            *p_err = DNSc_ERR_NAME_NOT_EXIST;
             goto exit;

        default:
            *p_err = DNSc_ERR_BAD_RESPONSE_TYPE;
             goto exit;
    }


    Mem_Copy(&question_nbr, &p_dns_msg->QuestionNbr, sizeof(p_dns_msg->QuestionNbr));
    question_nbr = NET_UTIL_NET_TO_HOST_16(question_nbr);
    if (question_nbr != DNSc_QUESTION_NBR) {                    /* If nbr of question do not match the query,       ... */
       *p_err = DNSc_ERR_BAD_QUESTION_COUNT;                    /* ... rtn err.                                         */
        return;
    }

    Mem_Copy(&answer_nbr, &p_dns_msg->AnswerNbr, sizeof(p_dns_msg->AnswerNbr));
    answer_nbr = NET_UTIL_NET_TO_HOST_16(answer_nbr);
    if (answer_nbr < DNSc_ANSWER_NBR_MIN) {                     /* If nbr of answer is null,                        ... */
       *p_err = DNSc_ERR_NONE;                                  /* No answer for this type of request.                  */
        return;
    }

                                                                /* Skip over the questions section.                     */
    p_data = &p_dns_msg->QueryMsg;

    for (ix = 0u; ix < question_nbr; ix++) {

        while (*p_data != ASCII_CHAR_NULL) {                    /* Step through the host name until reaching the ZERO.  */
            p_data += *p_data;
            p_data++;
        }

        p_data += (DNSc_ZERO_CHAR_SIZE +                        /* Skip over the ZERO.                                  */
                   DNSc_PKT_TYPE_SIZE  +                        /* Skip over the TYPE.                                  */
                   DNSc_PKT_CLASS_SIZE);                        /* Skip over the CLASS.                                 */
    }



                                                                /* Extract the rtn'd IP addr (see Note #5).             */
    for (ix = 0; ix < answer_nbr; ix++) {

                                                                /* Skip over the answer host name.                      */
        if ((*p_data & DNSc_COMP_ANSWER) == DNSc_COMP_ANSWER) { /* If the host name is compressed,                  ... */
             p_data  += DNSc_HOST_NAME_PTR_SIZE;                /* ... skip over the host name pointer.                 */

        } else {

            while (*p_data != ASCII_CHAR_NULL) {                /* Step through the host name until reaching the ZERO.  */
                p_data += *p_data;
                p_data++;
            }

            p_data += DNSc_ZERO_CHAR_SIZE;                      /* Skip over the ZERO.                                  */
        }



        Mem_Copy(&answer_type, p_data, sizeof(CPU_INT16U));
        answer_type =  NET_UTIL_NET_TO_HOST_16(answer_type);    /* Get answer TYPE.                                     */

        p_data += (DNSc_PKT_TYPE_SIZE  +                        /* Skip over the CLASS & the TTL.                       */
                   DNSc_PKT_CLASS_SIZE +
                   DNSc_PKT_TTL_SIZE);


        Mem_Copy(&data_16, p_data, sizeof(CPU_INT16U));
        data_16 = NET_UTIL_NET_TO_HOST_16(data_16);             /* Addr len.                                            */
        p_data += sizeof(CPU_INT16U);

        DNScReq_RxRespAddAddr(p_cfg, p_host, answer_type, p_data, p_resp_msg, data_16, p_err);

        p_data += data_16;
    }

    *p_err = DNSc_ERR_NONE;


exit:
    return;
}


/*
*********************************************************************************************************
*                                        DNScReq_RxRespAddAddr()
*
* Description : Add address for the response message to the host.
*
* Argument(s) : p_cfg           Pointer to the DNSc configuration.
*
*               p_host          Pointer to the host object.
*
*               answer_type     Answer type.
*
*               p_data          Pointer to the data that contains the address.
*
*               p_resp_msg      Pointer to the start of full response to DNS request.
*
*               answer_size     Size of answer to DNS query.
*
*               p_err           Pointer to variable that will receive the return error code from this function :
*
*                                   DNSc_ERR_NONE               Address successfully added to the host object.
*                                   DNSc_ERR_BAD_RESPONSE_TYPE  Unknown answer type.
*
*                                   RETURNED BY DNScCache_AddrObjGet():
*                                       See DNScCache_AddrObjGet() for additional return error codes.
*
*                                   RETURNED BY DNScCache_HostAddrInsert():
*                                       See DNScCache_HostAddrInsert() for additional return error codes.
*
* Return(s)   : None.
*
* Caller(s)   : DNScReq_RxRespMsg().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScReq_RxRespAddAddr (const  DNSc_CFG       *p_cfg,
                                            DNSc_HOST_OBJ  *p_host,
                                            CPU_INT16U      answer_type,
                                            CPU_INT08U     *p_data,
                                            CPU_INT08U     *p_resp_msg,
                                            CPU_INT16U      answer_size,
                                            DNSc_ERR       *p_err)
{
    DNSc_ADDR_OBJ  *p_addr;
    CPU_CHAR       *p_char;
    CPU_BOOLEAN     is_reverse;
    CPU_BOOLEAN     is_canonical;
    CPU_BOOLEAN     is_compressed;
    CPU_SIZE_T      data_len;
    CPU_INT08U      hostname_len;
    CPU_INT08U      append_len;
    CPU_INT08U      i;
    CPU_BOOLEAN     is_ctrl_char;


    is_reverse    =   (answer_type == DNSc_TYPE_PTR);
    is_canonical  =   (answer_type == DNSc_TYPE_CNAME);
    is_compressed = (*(p_data + (answer_size - DNSc_HOST_NAME_PTR_SIZE)) == DNSc_COMP_ANSWER);

    if ((!is_reverse) && (!is_canonical)) {
        p_addr = DNScCache_AddrObjGet(p_err);
        if (*p_err != DNSc_ERR_NONE) {
            goto exit;
        }
    }

    switch (answer_type) {
        case DNSc_TYPE_A:
             Mem_Copy(&p_addr->Addr, p_data, sizeof(CPU_INT32U));
           *(CPU_INT32U *)p_addr->Addr = NET_UTIL_NET_TO_HOST_32(*(CPU_INT32U *)p_addr->Addr);
             p_addr->Len               = NET_IPv4_ADDR_LEN;
             break;


        case DNSc_TYPE_AAAA:
             Mem_Copy(p_addr->Addr, p_data, NET_IPv6_ADDR_LEN);
             p_addr->Len = NET_IPv6_ADDR_LEN;
             break;


        case DNSc_TYPE_CNAME:
             if (p_host->CanonicalNamePtr != (CPU_CHAR *)DEF_NULL) {
                 data_len = answer_size;
                 Mem_Clr(p_host->CanonicalNamePtr, p_host->NameLenMax);

                 p_char = (CPU_CHAR *)p_data;

                 for (i = 0u; i < data_len; i++) {              /* Replace control characters with '.' character.       */
                      is_ctrl_char = ASCII_IsCtrl(*p_char);
                      if (is_ctrl_char) {
                         *p_char = '.';
                          if (i == 0u) {                        /* Ignore '.' character at the beginning of host name.  */
                              p_data++;
                              data_len--;
                          }
                      }
                      p_char++;
                 }
                 p_char = (CPU_CHAR *)p_data;

                                                                /* Copy data_len bytes from msg to canonical name.      */
                 Str_Copy_N(p_host->CanonicalNamePtr, p_char, DEF_MIN(p_host->NameLenMax, data_len));

                                                                /* Check penultimate byte for '0xC0' token. If found,...*/
                                                                /*...the last byte contains an offset value that if ... */
                                                                /*...added to the begining of DNS response will point...*/
                                                                /*...to the rest of (NULL-terminated) canonical name.   */
                                                                /* (See Note #2 in the "DNS TYPE DEFINE" section above).*/
                 if (*(p_host->CanonicalNamePtr + data_len - 1u) == DNSc_COMP_ANSWER) {
                     append_len = Str_Len_N((CPU_CHAR *)p_resp_msg, *(p_data + data_len));
                 }

                 hostname_len = Str_Len(p_host->CanonicalNamePtr);
                                                                /* Append rest of canonical name.                       */
                 if ((is_compressed == DEF_TRUE) && ((hostname_len + append_len) < p_host->NameLenMax)) {
                     p_char = ((CPU_CHAR *)p_resp_msg + *(p_host->CanonicalNamePtr + data_len - 1u));
                     Str_Copy_N(p_host->CanonicalNamePtr + hostname_len - DNSc_HOST_NAME_PTR_SIZE,
                                p_char,
                                p_host->NameLenMax);
                 }
             }

            *p_err = DNSc_ERR_NONE;
             goto exit;


        case DNSc_TYPE_PTR:
             data_len = Str_Len_N((const CPU_CHAR *)p_data, p_host->NameLenMax);
             p_char   = (CPU_CHAR *)p_data;

             for (i = 0u; i < data_len; i++) {                  /* Replace control characters with '.' character.       */
                  is_ctrl_char = ASCII_IsCtrl(*p_char);
                  if (is_ctrl_char) {
                     *p_char = '.';
                  }
                  p_char++;
             }
             p_char = (CPU_CHAR *)(p_data + 1u);               /* Ignore first character of the host name.              */

             Str_Copy_N(p_host->ReverseNamePtr, p_char, p_host->NameLenMax);
            *p_err = DNSc_ERR_NONE;
             goto exit;


        default:
            *p_err = DNSc_ERR_BAD_RESPONSE_TYPE;
             goto exit_release_addr;
    }

    DNScCache_HostAddrInsert(p_cfg, p_host, p_addr, is_reverse, p_err);
    if ((*p_err != DNSc_ERR_NONE) && (!is_reverse)) {
        goto exit_release_addr;
    }

    goto exit;


exit_release_addr:
    DNScCache_AddrObjFree(p_addr);

exit:
    return;
}


/*
*********************************************************************************************************
*                                           DNScReq_TxData()
*
* Description : Transmit data on the network
*
* Argument(s) : sock_id     Socket ID.
*
*               p_buf       Pointer to the buffer that contains the data to transmit.
*
*               data_len    Data length to transmit.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE       Data successfully transmitted.
*                               DNSc_ERR_TX         Unable to transmit the data (should retry later).
*                               DNSc_ERR_TX_FAULT   Network socket fault (socket must be closed).
*
* Return(s)   : None.
*
* Caller(s)   : DNScReq_TxReq().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  void  DNScReq_TxData (NET_SOCK_ID   sock_id,
                              CPU_INT08U   *p_buf,
                              CPU_INT16U    data_len,
                              DNSc_ERR     *p_err)
{
    CPU_INT32S    data_txd;
    CPU_INT08U   *p_data     = p_buf;
    CPU_INT08U    fail_retry = 0u;
    CPU_INT32U    len        = data_len;
    CPU_BOOLEAN   req_done   = DEF_NO;
    NET_ERR       net_err;


    do {
                                                                /* Tx DNS req.                                          */
        data_txd = NetSock_TxData(sock_id,
                                  p_data,
                                  data_len,
                                  NET_SOCK_FLAG_TX_NO_BLOCK,
                                 &net_err);
        switch (net_err) {
            case NET_SOCK_ERR_NONE:
                 if (data_txd > 0) {
                     p_data += data_txd;
                     len    -= data_txd;
                 }

                 if (len <= 0) {
                     req_done = DEF_YES;
                 }
                 break;

            case NET_ERR_TX:                                    /* Retry on transitory tx err(s).                       */
                 if ((len        > 0u) &&
                     (fail_retry < DNSc_SOCK_TX_RETRY_MAX)) {

                     KAL_Dly(DNSc_SOCK_TX_DLY_MS);
                     fail_retry++;

                 } else {
                    *p_err = DNSc_ERR_TX;
                     goto exit;
                 }
                 break;

            case NET_ERR_IF_LINK_DOWN:
                 *p_err = DNSc_ERR_IF_LINK_DOWN;
                  goto exit;

            default:                                            /* Rtn   on any fatal  tx err(s).                       */
                *p_err = DNSc_ERR_TX_FAULT;
                 goto exit;
        }

    } while (req_done != DEF_YES);


   *p_err = DNSc_ERR_NONE;

exit:
    return;
}


/*
*********************************************************************************************************
*                                           DNScReq_RxData()
*
* Description : Receive data from the network.
*
* Argument(s) : sock_id     Socket ID.
*
*               p_buf       Pointer to the buffer that will receive the data.
*
*               data_len    Buffer length.
*
*               p_err       Pointer to variable that will receive the return error code from this function :
*
*                               DNSc_ERR_NONE       Data has been received successfully.
*                               DNSc_ERR_RX         No data has been received.
*                               DNSc_ERR_RX_FAULT   Network socket fault (socket must be closed).
*
* Return(s)   : Number of bytes received.
*
* Caller(s)   : DNScReq_RxResp().
*
* Note(s)     : None.
*********************************************************************************************************
*/

static  CPU_INT16U  DNScReq_RxData (NET_SOCK_ID   sock_id,
                                    CPU_INT08U   *p_buf,
                                    CPU_INT16U    buf_len,
                                    DNSc_ERR     *p_err)
{
    CPU_INT32S  rx_len  = 0;
    NET_ERR     net_err;


    rx_len  = NetSock_RxData(sock_id,
                             p_buf,
                             buf_len,
                             NET_SOCK_FLAG_RX_NO_BLOCK,
                            &net_err);
    switch (net_err) {
        case NET_SOCK_ERR_NONE:
             break;

        case NET_SOCK_ERR_RX_Q_EMPTY:
             rx_len = 0;
            *p_err  = DNSc_ERR_RX;
             goto exit;

        default:                                /* Rtn   on any fatal  rx err(s).                       */
            *p_err = DNSc_ERR_RX_FAULT;
             goto exit;
    }


   *p_err = DNSc_ERR_NONE;

exit:
    return ((CPU_INT16U)rx_len);
}

