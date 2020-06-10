#ifndef _INF_8021x_WIRED_
#define _INF_8021x_WIRED_

#include <sys/types.h>
#include <inttypes.h>

#define INFWIRED_MSG_TYPE_EAPOL_DATA (0x1)
#define INFWIRED_MSG_TYPE_AUTH_DATA (0x2)
#define INFWIRED_MSG_TYPE_MAB_DATA (0x3)

struct infwired_paemsg_hdr {
    uint8_t paem_msgtype;
} __attribute__((packed));

struct infwired_auth_data {
    uint8_t iad_auth;
    uint8_t iad_sta[6];
} __attribute__((packed));

#endif