#ifndef ARK_PB_TASK_TYPES_H
#define ARK_PB_TASK_TYPES_H

/* Generated from proto/c2.proto enum TaskType. Do not edit.
 * Regenerate with: make proto
 */

#define ARK_TASK_UNKNOWN           0
#define ARK_TASK_SHELL             1
#define ARK_TASK_FILE_DOWNLOAD     2
#define ARK_TASK_FILE_UPLOAD       3
#define ARK_TASK_PROCESS_LIST      4
#define ARK_TASK_PROCESS_KILL      5
#define ARK_TASK_NET_IFCONFIG      6
#define ARK_TASK_NET_PORTSCAN      7
#define ARK_TASK_CREDS_DUMP        8
#define ARK_TASK_SCREENSHOT        9
#define ARK_TASK_KEYLOG_START      10
#define ARK_TASK_KEYLOG_STOP       11
#define ARK_TASK_KEYLOG_DUMP       12
#define ARK_TASK_PIVOT_START       13
#define ARK_TASK_PIVOT_STOP        14
#define ARK_TASK_INJECT            15
#define ARK_TASK_PE_LOAD           16
#define ARK_TASK_SOCKS_START       17
#define ARK_TASK_SOCKS_STOP        18
#define ARK_TASK_EXIT              19
#define ARK_TASK_SLEEP             20
#define ARK_TASK_MODULE            21
#define ARK_TASK_LDAP_ENUM         22
#define ARK_TASK_KERBEROAST        23
#define ARK_TASK_ASREPROAST        24
#define ARK_TASK_LATERAL_MOVE      25
#define ARK_TASK_PE_LOAD_EXEC      26
#define ARK_TASK_PERSIST           27
#define ARK_TASK_PRIVESC           28

#define ARK_TASK_TYPE_MIN          0
#define ARK_TASK_TYPE_MAX          28

#endif
