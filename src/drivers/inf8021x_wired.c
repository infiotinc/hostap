// -----------------------------------------------------------------------------
//  Copyright (c) 2020 Infiot Inc.
//  All Rights Reserved.
// -----------------------------------------------------------------------------
#include "includes.h"
#include "stdio.h"
#include "stddef.h"
#include "common.h"
#include "driver.h"
#include "eloop.h"
#include <sys/types.h>
#include <sys/un.h>
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "inf8021x_wired.h"
#include "ap/hostapd.h"
#include "ap/sta_info.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"

#define INFWIRED_DSOCK_BASE "/infroot/workdir/8021x"

static const u8 pae_group_addr[ETH_ALEN] =
    {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

/*
 * Compact form for string representation of MAC address
 * To be used, e.g., for constructing dbus paths for P2P Devices
 */
#define COMPACT_MACSTR "%02x%02x%02x%02x%02x%02x"
#endif

struct ieee8023_hdr {
	u8 dest[6];
	u8 src[6];
	u16 ethertype;
} STRUCT_PACKED;

struct driver_infwired_common_data {
    void *ctx;

    char ifname[IFNAMSIZ + 1];
    int sock;                    // UNIX socket to the dataplane/port manager
    struct sockaddr_un sockattr; // UNIX socket name to the port manager
};

struct wpa_driver_infwired_data {
    struct driver_infwired_common_data common;
    int dhcp_sock; /* socket for dhcp packets */
    int use_pae_group_addr;
};

static int infwired_common_init_sockets(struct driver_infwired_common_data *cd);
static void handle_read(int sock, void *eloop_ctx, void *sock_ctx);

static void unix_socket_block_till_connect(int sk, struct sockaddr_un *skattr)
{
    uint8_t connected = 0;
    int ret = 0;
    while (!connected) {
        ret = 0;
        ret = connect(sk,
                      (struct sockaddr *)skattr,
                      sizeof(struct sockaddr_un));
        if (ret < 0) {
            sleep(5);
            continue;
        }

        connected = 1;
    }

    return;
}

static void handle_eapol_mode(void *ctx, unsigned char *buf, size_t len)
{
    wpa_printf(MSG_INFO, "INFWIRED: Handle EAPOL mode");
	struct ieee8023_hdr *hdr;
	u8 *pos, *sa;
	size_t left;
	union wpa_event_data event;

	hdr = (struct ieee8023_hdr *) (buf + sizeof(struct infwired_paemsg_hdr));

	switch (ntohs(hdr->ethertype)) {
	case ETH_P_PAE:
		wpa_printf(MSG_MSGDUMP, "Received EAPOL packet");
		sa = hdr->src;
		os_memset(&event, 0, sizeof(event));
		event.new_sta.addr = sa;
        struct hostapd_data *hapd = (struct hostapd_data *)ctx;
        struct sta_info *sta = ap_get_sta(hapd, &hdr->src[0]);
        if (sta && sta->eapol_sm->auth_pae_state == AUTH_PAE_AUTHENTICATED) {
            u8* eapol_hdr = (u8*)(hdr + 1);
            if (eapol_hdr[1] == 1) {
                wpa_printf(MSG_INFO, "INFWIRED: PAE authencitcated, disconnecting");
                ap_sta_deauthenticate(hapd, sta, WLAN_REASON_UNSPECIFIED);
            }
        }
		wpa_supplicant_event(ctx, EVENT_NEW_STA, &event);

		pos = (u8 *) (hdr + 1);
		left = len - sizeof(*hdr);
		drv_event_eapol_rx(ctx, sa, pos, left);
		break;

	default:
		wpa_printf(MSG_DEBUG, "Unknown ethertype 0x%04x in data frame",
			   ntohs(hdr->ethertype));
		break;
	}

}

static void handle_mab_mode(void *ctx, unsigned char *buf, size_t len)
{
    wpa_printf(MSG_INFO, "INFWIRED: Handle MAB mode");

    struct hostapd_data *hapd = ctx;
    struct radius_msg *msg;
    int radiusid;
	struct ieee8023_hdr *hdr;
    char identity[128] = {0};
    size_t identitylen = ETH_ALEN;
    char nullmac[ETH_ALEN] = {0};

    if (!(hapd->radius)) {
        wpa_printf(MSG_WARNING, "INFWIRED: radius client not connected");
        return;
    }

    radiusid = radius_client_get_id(hapd->radius);
	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, radiusid);
	if (msg == NULL) {
		wpa_printf(MSG_ERROR, "Could not create new RADIUS packet");
		return;
	}

	if (radius_msg_make_authenticator(msg) < 0) {
		wpa_printf(MSG_ERROR, "Could not make Request Authenticator");
        radius_msg_free(msg);
        return;
	}

    hdr = (struct ieee8023_hdr *) (buf + sizeof(struct infwired_paemsg_hdr));
	os_snprintf(identity,
                sizeof(identity),
                RADIUS_ADDR_FORMAT,
                MAC2STR(hdr->src));
    // add first and only station (when the query is empty)
    if (memcmp(hapd->mab_acl_query.addr, nullmac, ETH_ALEN) == 0) {
	    union wpa_event_data event;
     	os_memset(&event, 0, sizeof(event));
		event.new_sta.addr = &hdr->src[0];
        struct sta_info *sta = ap_sta_add(hapd, &hdr->src[0]);
        if (!sta) {
            wpa_printf(MSG_ERROR, "INFWIRED: error creating a station");
            return;
        }
        ap_sta_set_mab(sta, 1);
    }

    if (!radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME,
                             (u8 *)identity, identitylen)) {
        printf("Could not add User-Name\n");
        radius_msg_free(msg);
        return;
    }

    if (!radius_msg_add_attr_user_password(
            msg, (u8 *)identity, identitylen,
            hapd->conf->radius->auth_server->shared_secret,
            hapd->conf->radius->auth_server->shared_secret_len)) {
        printf("Could not add User-Password\n");
        radius_msg_free(msg);
        return;
    }

	os_snprintf(identity, sizeof(identity), RADIUS_802_1X_ADDR_FORMAT,
		        MAC2STR(hdr->src));
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
				 (u8 *) identity, os_strlen(identity))) {
		wpa_printf(MSG_ERROR, "Could not add Calling-Station-Id");
		return;
	}

    hapd->mab_acl_query.radius_id = radiusid;
    memcpy(hapd->mab_acl_query.addr, hdr->src, ETH_ALEN);
    hapd->mab_acl_query.next = NULL;
    if (radius_client_send(hapd->radius, msg, RADIUS_AUTH, NULL) < 0) {
        radius_msg_free(msg);
    }

    return;
}

static void handle_data(void *ctx, unsigned char *buf, size_t len)
{
    wpa_printf(MSG_INFO, "data %p received size %lu", buf, len);

    struct infwired_paemsg_hdr *fullhdr;

	/* must contain at least ieee8023_hdr 6 byte source, 6 byte dest,
	 * 2 byte ethertype */
	if (len < 14) {
		wpa_printf(MSG_MSGDUMP, "handle_data: too short (%lu)",
			   (unsigned long) len);
		return;
	}

    fullhdr = (struct infwired_paemsg_hdr *)buf;

    if (fullhdr->paem_msgtype == INFWIRED_MSG_TYPE_EAPOL_DATA) {
        handle_eapol_mode(ctx, buf, len);
        return;
    }

    if (fullhdr->paem_msgtype == INFWIRED_MSG_TYPE_MAB_DATA) {
        handle_mab_mode(ctx, buf, len);
        return;
    }
}

static void infwired_data_sock_close(struct wpa_driver_infwired_data *drv)
{
    if (drv->common.sock == -1) {
        return;
    }

    eloop_unregister_read_sock(drv->common.sock);
    close(drv->common.sock);
    drv->common.sock = -1;

    return;
}

static int infwired_send_sta_info(struct hostapd_data *hapd,
                                  struct sta_info *sta,
                                  void *ctx)
{
    struct infwired_paemsg_hdr *fullhdr;
    struct infwired_auth_data *authdata;
    u8 *buf;
    size_t len;
    int authorized = 0;
    int auth_state = 0;
    struct wpa_driver_infwired_data *drv = ctx;

    if (sta->eapol_sm) {
        wpa_printf(MSG_INFO, "INFWIRED: Sending STA info - "
                   "ifname=%s addr=" MACSTR "auth_state=%d",
                   drv->common.ifname,
                   MAC2STR(sta->addr),
                   sta->eapol_sm->auth_pae_state);
        auth_state = sta->eapol_sm->auth_pae_state;
        if (auth_state == AUTH_PAE_AUTHENTICATED) {
            authorized = 1;
        }
    }

    len = sizeof(*fullhdr) + sizeof(struct infwired_auth_data);
    buf = os_zalloc(len);
    if (buf == NULL) {
        wpa_printf(MSG_INFO,
                   "malloc() failed for wired_send_eapol(len=%lu)",
                   (unsigned long)len);
        return -1;
    }

    fullhdr = (struct infwired_paemsg_hdr *)buf;
    fullhdr->paem_msgtype = INFWIRED_MSG_TYPE_AUTH_DATA;
    authdata = (struct infwired_auth_data *)(buf + sizeof(*fullhdr));
    authdata->iad_auth = authorized;
    memcpy(authdata->iad_sta, sta->addr, ETH_ALEN);
    wpa_printf(MSG_INFO, "INFWIRED: Sending STA info - ifname=%s addr=" MACSTR
		   " auth_state=0x%x authorized=%d",
		   drv->common.ifname,
           MAC2STR(sta->addr),
		   auth_state,
           authorized);
    int res = send(drv->common.sock, (u8 *)buf, len, 0);
    os_free(buf);

    if (res < 0) {
        wpa_printf(MSG_ERROR,
                   "wired_send_eapol - packet len: %lu - failed: send: %s",
                   (unsigned long)len, strerror(errno));
        return -1;
    }

    return 0;
}

static void infwired_connect_to_pae_server(struct wpa_driver_infwired_data *drv)
{
    unix_socket_block_till_connect(drv->common.sock, &drv->common.sockattr);
    wpa_printf(MSG_INFO, "INFWIRED: connected to port manager socket %s",
               drv->common.sockattr.sun_path);

    // the first message to the external PAE manager is a list of existing
    // stations
    if (drv->common.ctx) {
        struct hostapd_data *hapd = (struct hostapd_data*)drv->common.ctx;
        ap_for_each_sta(hapd, infwired_send_sta_info, drv);
    }
    eloop_register_read_sock(drv->common.sock,
                             handle_read,
                             drv,
                             NULL);

}

static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];
    struct wpa_driver_infwired_data *drv = eloop_ctx;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "INFWIRED recv: %s", strerror(errno));
		return;
	}

    if (len == 0) {
        wpa_printf(MSG_ERROR, "INFWIRED: connection to PAE reset err %s",
                   strerror(errno));
        infwired_data_sock_close(drv);
        infwired_common_init_sockets(&drv->common);
        wpa_printf(MSG_INFO, "reconnceting to the external PAE");
        infwired_connect_to_pae_server(drv);
        return;        
    }

    wpa_printf(MSG_INFO, "INFWIRED: recieved data from PAEMgr len=%d", len);
	handle_data(drv->common.ctx, buf, len);
}

static int infwired_common_init_sockets(struct driver_infwired_common_data *cd)
{
    cd->sock = -1;
    cd->sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (cd->sock < 0) {
        wpa_printf(MSG_ERROR, "could not open socket to port manager err=%d",
                   errno);
        return -1;
    }

    memset(&cd->sockattr, 0, sizeof(struct sockaddr_un));
    cd->sockattr.sun_family = AF_UNIX;
    snprintf(cd->sockattr.sun_path,
             sizeof(cd->sockattr.sun_path) - 1,
             "%s%s",
             INFWIRED_DSOCK_BASE, cd->ifname);
    wpa_printf(MSG_INFO, "INFWIRED: opening socket to port manager %s",
               cd->sockattr.sun_path);

    return 0;
}

static int infwired_common_deinit(struct driver_infwired_common_data *cd)
{
    if (cd->sock != -1) {
        close(cd->sock);
    }

    return 0;
}

static void *infwired_driver_hapd_init(struct hostapd_data *hapd,
                                       struct wpa_init_params *params)
{
    struct wpa_driver_infwired_data *drv = NULL;

    wpa_printf(MSG_INFO, "INFWIRED: Initializing hostapd infwired driver");

    drv = os_zalloc(sizeof(struct wpa_driver_infwired_data));
    if (drv == NULL) {
        wpa_printf(MSG_INFO,
                   "INFWIRED: Could not allocate memory for wired driver data");
        return NULL;
    }

    drv->common.ctx = hapd;
    os_strlcpy(drv->common.ifname, params->ifname,
               sizeof(drv->common.ifname));
    drv->use_pae_group_addr = 1; //params->use_pae_group_addr;

    if (infwired_common_init_sockets(&drv->common)) {
        os_free(drv);
        return NULL;
    }

    infwired_connect_to_pae_server(drv);
    return drv;
}

static void infwired_driver_hapd_deinit(void *priv)
{
    struct wpa_driver_infwired_data *drv = priv;

    eloop_unregister_read_sock(drv->common.sock);

    infwired_common_deinit(&drv->common);
    os_free(drv);
}

static int driver_infwired_get_ssid(void *priv, u8 *ssid)
{
    ssid[0] = 0;
    return 0;
}

static int driver_infwired_get_bssid(void *priv, u8 *bssid)
{
    /* Report PAE group address as the "BSSID" for wired connection. */
    os_memcpy(bssid, pae_group_addr, ETH_ALEN);
    return 0;
}

int driver_infwired_get_capa(void *priv, struct wpa_driver_capa *capa)
{
	os_memset(capa, 0, sizeof(*capa));
	capa->flags = WPA_DRIVER_FLAGS_WIRED;
	return 0;
}


static int infwired_send_eapol(void *priv, const u8 *addr,
                               const u8 *data, size_t data_len, int encrypt,
                               const u8 *own_addr, u32 flags)
{
    wpa_printf(MSG_INFO, "INFWIRED: send EAPOL data len=%lu", data_len);
    struct wpa_driver_infwired_data *drv = priv;
    struct infwired_paemsg_hdr *fullhdr;
    u8 *buf;
    size_t len;
    u8 *pos;
    int res;

    len = sizeof(*fullhdr) + sizeof(struct ieee8023_hdr) + data_len;
    buf = os_zalloc(len);
    if (buf == NULL) {
        wpa_printf(MSG_INFO,
                   "malloc() failed for wired_send_eapol(len=%lu)",
                   (unsigned long)len);
        return -1;
    }

    fullhdr = (struct infwired_paemsg_hdr *)buf;
    fullhdr->paem_msgtype = INFWIRED_MSG_TYPE_EAPOL_DATA;
    struct ieee8023_hdr *hdr = (struct ieee8023_hdr *)
        (buf + sizeof(struct infwired_paemsg_hdr));
    os_memcpy(hdr->dest,
              drv->use_pae_group_addr ? pae_group_addr : addr,
              ETH_ALEN);
    os_memcpy(hdr->src, own_addr, ETH_ALEN);
    hdr->ethertype = htons(ETH_P_PAE);

    pos = (u8 *)(hdr + 1);
    os_memcpy(pos, data, data_len);

    res = send(drv->common.sock, (u8 *)buf, len, 0);
    os_free(buf);

    if (res < 0) {
        wpa_printf(MSG_ERROR,
                   "wired_send_eapol - packet len: %lu - failed: send: %s",
                   (unsigned long)len, strerror(errno));
    }

    return res;
}

static int driver_infwired_set_deauth(void *priv, 
            const u8 *own_addr, const u8 *addr,
			u16 reason)
{
    struct wpa_driver_infwired_data *drv = priv;
    wpa_printf(MSG_INFO, "INFWIRED: deauthenticating interface %s",
               drv->common.ifname);
    return 0;
}

static void *wpa_driver_infwired_init(void *ctx, const char *ifname)
{
    struct wpa_driver_infwired_data *drv;

    drv = os_zalloc(sizeof(*drv));
    if (drv == NULL)
        return NULL;

    wpa_printf(MSG_INFO, "Initializing WPA infwired driver");
    // if (driver_wired_init_common(&drv->common, ifname, ctx) < 0) {
    // 	os_free(drv);
    // 	return NULL;
    // }

    return drv;
}

static void wpa_driver_infwired_deinit(void *priv)
{
    struct wpa_driver_infwired_data *drv = priv;

    infwired_common_deinit(&drv->common);
    os_free(drv);
}

static int wpa_driver_infwired_sta_set_flags(void *priv, const u8 *addr,
					                         unsigned int total_flags,
					                         unsigned int flags_or,
					                         unsigned int flags_and)
{
    struct wpa_driver_infwired_data *drv = priv;
    int authorized = !!(total_flags & WPA_STA_AUTHORIZED);
    struct infwired_paemsg_hdr *fullhdr;
    struct infwired_auth_data *authdata;
    u8 *buf;
    size_t len;

    len = sizeof(*fullhdr) + sizeof(struct infwired_auth_data);
    buf = os_zalloc(len);
    if (buf == NULL) {
        wpa_printf(MSG_INFO,
                   "malloc() failed for wired_send_eapol(len=%lu)",
                   (unsigned long)len);
        return -1;
    }

    fullhdr = (struct infwired_paemsg_hdr *)buf;
    fullhdr->paem_msgtype = INFWIRED_MSG_TYPE_AUTH_DATA;
    authdata = (struct infwired_auth_data *)(buf + sizeof(*fullhdr));
    authdata->iad_auth = authorized;
    memcpy(authdata->iad_sta, addr, ETH_ALEN);
    wpa_printf(MSG_INFO, "INFWIRED: Set STA flags - ifname=%s addr=" MACSTR
		   " total_flags=0x%x flags_or=0x%x flags_and=0x%x authorized=%d",
		   drv->common.ifname, MAC2STR(addr), total_flags, flags_or, flags_and,
		   !!(total_flags & WPA_STA_AUTHORIZED));
    int res = send(drv->common.sock, (u8 *)buf, len, 0);
    os_free(buf);

    if (res < 0) {
        wpa_printf(MSG_ERROR,
                   "wired_send_eapol - packet len: %lu - failed: send: %s",
                   (unsigned long)len, strerror(errno));
    }

    return 0;
}

const struct wpa_driver_ops wpa_driver_infwired_ops = {
    .name = "infwired",
    .desc = "Infiot 8021x Wired Ethernet driver",
    .hapd_init = infwired_driver_hapd_init,
    .hapd_deinit = infwired_driver_hapd_deinit,
    .hapd_send_eapol = infwired_send_eapol,
    .get_ssid = driver_infwired_get_ssid,
    .get_bssid = driver_infwired_get_bssid,
    .get_capa = driver_infwired_get_capa,
    .sta_deauth = driver_infwired_set_deauth,
    .init = wpa_driver_infwired_init,
    .deinit = wpa_driver_infwired_deinit,
    .sta_set_flags = wpa_driver_infwired_sta_set_flags,
};
