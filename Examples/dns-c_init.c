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
*                                      DNS CLIENT INITIALIZATION
*
* Filename : dns-c_init.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) This example shows how to initialize uC/DNSc correctly.
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

#include  <dns-c_cfg.h>
#include  <Source/dns-c.h>


/*
*********************************************************************************************************
*                                            AppInit_DNSc()
*
* Description : This function initialize uC/DNSc. This function returns only the DHCP negotiation is completed.
*
* Argument(s) : None.
*
* Return(s)   : DEF_OK,   Completed successfully.
*
*               DEF_FAIL, Initialization failed.
*
* Caller(s)   : Application.
*
* Note(s)     : (1) Prior to do any call to DNS client the module must be initialized. If the process is successful,
*                   the DNS client s tasks are started (if applicable), and its various data structures are initialized.
*********************************************************************************************************
*/

CPU_BOOLEAN  AppDNSc_Init (void)
{
    DNSc_ERR  dns_err;

                                                                /* --------------- INITIALIZE uC/DHCPc ---------------- */
                                                                /* See Note #1.                                         */
#if (DNSc_CFG_MODE_ASYNC_EN == DEF_DISABLED)
    DNSc_Init(&DNSc_Cfg, DEF_NULL, &dns_err);

#else
    DNSc_Init(&DNSc_Cfg, &DNSc_CfgTask, &dns_err);
#endif

    if (dns_err != DNSc_ERR_NONE) {
        return (DEF_FAIL);

    }

    return (DEF_OK);
}

