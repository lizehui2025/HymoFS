/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * HymoFS - tracepoint-based syscall monitoring header.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */
#ifndef _HYMOFS_TRACEPOINT_H
#define _HYMOFS_TRACEPOINT_H

int hymofs_tracepoint_path_init(void);
void hymofs_tracepoint_path_exit(void);
int hymofs_tracepoint_path_registered(void);
int hymofs_tracepoint_getfd_registered(void);

void hymofs_handle_sys_enter_cmdline(struct pt_regs *regs, long id);
void hymofs_handle_sys_exit_cmdline(struct pt_regs *regs, long ret);

#endif /* _HYMOFS_TRACEPOINT_H */
