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
*                                    ADD DNS COMMANDS TO uC/SHELL
*
* Filename : dns-c_init_shell.c
* Version  : V2.02.00
*********************************************************************************************************
* Note(s)  : (1) This example shows how to initialize DNS client command for uC/Shell.
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

#include  <lib_def.h>
#include  <Cmd/dns-c_cmd.h>


/*
*********************************************************************************************************
*                                            AppInit_DNSc()
*
* Description : This function add all command of DNSc that can be executed by uC/Shell.
*
* Argument(s) : None.
*
* Return(s)   : DEF_OK,   Completed successfully.
*
*               DEF_FAIL, Initialization failed.
*
* Caller(s)   : Application.
*
* Note(s)     : (1) Prior to do any call to DNSc the module must be initialized.
*********************************************************************************************************
*/

CPU_BOOLEAN  AppDNScCmd_Init (void)
{
    DNSc_CMD_ERR  dns_cmd_err;


    DNScCmd_Init(&dns_cmd_err);
    if (dns_cmd_err != DNSc_CMD_ERR_NONE) {
        return (DEF_FAIL);
    }

    return (DEF_OK);
}

