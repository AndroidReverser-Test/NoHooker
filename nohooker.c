/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/cred.h>
#include <taskext.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <syscall.h>
#include <linux/string.h>
#include <kputils.h>
#include <asm/current.h>

KPM_NAME("nohooker");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("test");
KPM_DESCRIPTION("nohooker");

uintptr_t protect_start_addr,protect_end_addr;

int (*scnprintf)(char *buf, size_t size, const char* fmt, ...) = 0;
unsigned long (*simple_strtoul)(const char *cp, char **endp, unsigned int base) = 0;

void before_mprotect(hook_fargs3_t *args, void *udata){
    struct task_struct *task = current;
    struct cred* cred = *(struct cred**)((uintptr_t)task + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t*)((uintptr_t)cred + cred_offset.uid_offset);
    if(uid == 0){
        return;
    }
    unsigned long start_addr = (unsigned long)syscall_argn(args, 0);
    if(start_addr>=protect_start_addr && start_addr<=protect_end_addr){
        logkd("nohooker_log:uid:%d,protect_addr:%llx\n",uid,start_addr);
        args->ret = -1;
        args->skip_origin = 1;
    }

}

static long nohooker_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("nohooker init\n");
    scnprintf = (typeof(scnprintf))kallsyms_lookup_name("scnprintf");
    simple_strtoul = (typeof(simple_strtoul))kallsyms_lookup_name("simple_strtoul");
    hook_err_t err = inline_hook_syscalln(__NR_mprotect, 3, before_mprotect, 0, 0);;

    return 0;
}

static long nohooker_control0(const char *args, char *__user out_msg, int outlen)
{
    char echo[500];
    char start_addr[20];
    char end_addr[20];
    char *tstr = strstr(args,"-");
    if(tstr){
        int split_len = tstr-args;
        if(split_len==0){
            goto end;
        }
        strncpy(start_addr,args,split_len);
        strcpy(end_addr,args+split_len+1);
        char *tmp;
        if(likely(simple_strtoul)){
            protect_start_addr = simple_strtoul(start_addr,&tmp,16);
            protect_end_addr = simple_strtoul(end_addr,&tmp,16);
            if(protect_start_addr==0 || protect_end_addr==0){
                goto end;
            }
            logkd("nohooker_log: start_addr:%llx,end_addr:%llx\n",protect_start_addr,protect_end_addr);
        }
    }
    else{
        goto end;
    }

    if(likely(scnprintf)){
        scnprintf(echo, sizeof(echo), "success set start_addr:%llx,end_addr:%llx\n", protect_start_addr,protect_end_addr);
    }
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;

    end:
        strcat(echo,"input error! for example:XXXXX-XXXXX\n");
        compat_copy_to_user(out_msg, echo, sizeof(echo));
        return 0;
}

static long nohooker_exit(void *__user reserved)
{
    pr_info("nohooker exit ...\n");
    inline_unhook_syscall(__NR_mprotect, before_mprotect, 0);
    return 0;
}

KPM_INIT(nohooker_init);
KPM_CTL0(nohooker_control0);
KPM_EXIT(nohooker_exit);