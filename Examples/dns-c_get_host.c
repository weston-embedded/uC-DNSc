/*
*********************************************************************************************************
*                                            EXAMPLE CODE
*
*               This file is provided as an example on how to use Micrium products.
*
*               Please feel free to use any application code labeled as 'EXAMPLE CODE' in
*               your application products.  Example code may be used as is, in whole or in
*               part, or may be used as a reference only. This file can be modified as
*               required to meet the end-product requirements.
*
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*
*                                               EXAMPLE
*
*                                      DNS HOST NAME RESOLUTION
*
* Filename : dns-c_get_host.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) This example shows how to resolve an hostname using DNS client.
*
*            (2) This example is for :
*
*                  (b) uC/TCPIP - V3.01.00
*
*            (3) This file is an example about how to use uC/DNSc, It may not cover all case needed by a real
*                application. Also some modification might be needed, insert the code to perform the stated
*                actions wherever 'TODO' comments are found.
*
*                (a) This example is not fully tested, so it is not guaranteed that all cases are cover
*                    properly.
*********************************************************************************************************
*/

#include  <Source/dns-c.h>

#include  <Source/net_util.h>
#include  <Source/net_ascii.h>
#include  <Source/net_sock.h>


/*
*********************************************************************************************************
*                                       AppDNSc_GetHostMicrium()
*
* Description : This function resolve the hostname "micrium.com" and return the IP address of the host.
*
* Argument(s) : p_addr_str  Pointer to a string that will receive the IP address.
*
* Return(s)   : None.
*
* Caller(s)   : Application.
*
* Note(s)     : (1) Prior to do any call to DNSc the module must be initialized.
*********************************************************************************************************
*/

void  AppDNSc_GetHostMicrium (CPU_CHAR  *p_addr_str)
{
    DNSc_ADDR_OBJ  addrs[2u];
    CPU_INT08U     addr_nbr = 2u;
    CPU_INT08U     ix;
    DNSc_ERR       dns_err;


    DNSc_GetHost("micrium.com", DEF_NULL, 0u, addrs, &addr_nbr, DNSc_FLAG_NONE, DEF_NULL, &dns_err);
    if (dns_err != DNSc_ERR_NONE) {
        return;
    }

    for (ix = 0u; ix < addr_nbr; ix++) {
        NET_ERR   net_err;


        if (addrs[ix].Len == NET_IPv4_ADDR_LEN) {
#ifdef  NET_IPv4_MODULE_EN
            NET_IPv4_ADDR *p_addr = (NET_IPv4_ADDR *)addrs[ix].Addr;


            NetASCII_IPv4_to_Str(*p_addr, p_addr_str, NET_ASCII_LEN_MAX_ADDR_IP, &net_err);
#endif
        } else {
#ifdef  NET_IPv6_MODULE_EN
            NET_IPv6_ADDR *p_addr = (NET_IPv6_ADDR *)addrs[ix].Addr;


            NetASCII_IPv6_to_Str(p_addr, p_addr_str, DEF_NO, DEF_YES, &net_err);
#endif
        }
    }
}
