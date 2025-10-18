/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "WireGuard-ESP32.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"

#include "lwip/tcpip.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/netdb.h"

#include "esp32-hal-log.h"

extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
}

// Wireguard instance
static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

#define TAG "[WireGuard] "

#define WG_MUTEX_LOCK()                                \
  if (!sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) { \
    LOCK_TCPIP_CORE();                                  \
  }

#define WG_MUTEX_UNLOCK()                             \
  if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) { \
    UNLOCK_TCPIP_CORE();                               \
  }

bool WireGuard::begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort) {
	return begin(localIP, Subnet, Gateway, privateKey, WIREGUARDIF_MTU) &&
		addPeer(remotePeerAddress, remotePeerPort, remotePeerPublicKey, NULL,
				IPAddress(0, 0, 0, 0), IPAddress(0, 0, 0, 0), WIREGUARDIF_KEEPALIVE_DEFAULT);
}

bool WireGuard::begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, uint16_t mtu) {
	struct wireguardif_init_data wg;
	ip_addr_t ipaddr = IPADDR4_INIT(static_cast<uint32_t>(localIP));
	ip_addr_t netmask = IPADDR4_INIT(static_cast<uint32_t>(Subnet));
	ip_addr_t gateway = IPADDR4_INIT(static_cast<uint32_t>(Gateway));

	assert(privateKey != NULL);

	// Setup the WireGuard device structure
	wg.private_key = privateKey;
	wg.listen_port = WIREGUARDIF_DEFAULT_PORT;
	
	wg.bind_netif = NULL;

	// Register the new WireGuard network interface with lwIP
	WG_MUTEX_LOCK();
	wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&ipaddr), ip_2_ip4(&netmask), ip_2_ip4(&gateway), &wg, &wireguardif_init, &ip_input);
	WG_MUTEX_UNLOCK();
	if( wg_netif == nullptr ) {
		log_e(TAG "failed to initialize WG netif.");
		return false;
	}
	// Mark the interface as administratively up, link up flag is set automatically when peer connects
	WG_MUTEX_LOCK();
	netif_set_up(wg_netif);
	wg_netif->mtu = mtu;
	WG_MUTEX_UNLOCK();

	// Initialize the platform
	wireguard_platform_init();

	this->_is_initialized = true;
	return true;
}

bool WireGuard::addPeer(const char* address, uint16_t port, const char* publicKey, const char* preSharedKey, const IPAddress& allowedAddr, const IPAddress& allowedMask, uint16_t keep_alive) {
	struct wireguardif_peer peer;

	assert(address != NULL);
	assert(publicKey != NULL);
	assert(port != 0);

	// Initialise the first WireGuard peer structure
	wireguardif_peer_init(&peer);
	// If we know the endpoint's address can add here
	bool success_get_endpoint_ip = false;
    for(int retry = 0; retry < 5; retry++) {
        ip_addr_t endpoint_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
        struct addrinfo *res = NULL;
        struct addrinfo hint;
        memset(&hint, 0, sizeof(hint));
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));
        if( lwip_getaddrinfo(address, NULL, &hint, &res) != 0 ) {
			vTaskDelay(pdMS_TO_TICKS(2000));
			continue;
		}
		success_get_endpoint_ip = true;
        struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
        inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        lwip_freeaddrinfo(res);

        peer.endpoint_ip = endpoint_ip;
        log_i(TAG "%s is %3d.%3d.%3d.%3d"
			, address
            , (endpoint_ip.u_addr.ip4.addr >>  0) & 0xff
            , (endpoint_ip.u_addr.ip4.addr >>  8) & 0xff
            , (endpoint_ip.u_addr.ip4.addr >> 16) & 0xff
            , (endpoint_ip.u_addr.ip4.addr >> 24) & 0xff
            );
		break;
    }
	if( !success_get_endpoint_ip  ) {
		log_e(TAG "failed to get endpoint ip.");
		return false;
	}

	peer.public_key = publicKey;
	peer.preshared_key = preSharedKey;
	peer.keep_alive = keep_alive;
    {
        ip_addr_t allowed_ip = IPADDR4_INIT(static_cast<uint32_t>(allowedAddr));
        peer.allowed_ip = allowed_ip;
        ip_addr_t allowed_mask = IPADDR4_INIT(static_cast<uint32_t>(allowedMask));
        peer.allowed_mask = allowed_mask;
    }
	
	peer.endport_port = port;

	// Register the new WireGuard peer with the netwok interface
	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);
	if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
		// Start outbound connection to peer
        log_i(TAG "connecting wireguard...");
		wireguardif_connect(wg_netif, wireguard_peer_index);
	}

	return true;
}

bool WireGuard::begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort) {
	// Maintain compatiblity with old begin 
	auto subnet = IPAddress(255,255,255,255);
	auto gateway = IPAddress(0,0,0,0);
	return WireGuard::begin(localIP, subnet, gateway, privateKey, remotePeerAddress, remotePeerPublicKey, remotePeerPort);
}

void WireGuard::end() {
	if( !this->_is_initialized ) return;

	if (wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) {
		// Disconnect the WG interface.
		wireguardif_disconnect(wg_netif, wireguard_peer_index);
		// Remove peer from the WG interface
		wireguardif_remove_peer(wg_netif, wireguard_peer_index);
		wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
	}
	// Remove the WG interface;
	WG_MUTEX_LOCK();
	netif_remove(wg_netif);
	WG_MUTEX_UNLOCK();
	// Shutdown the wireguard interface.
	wireguardif_shutdown(wg_netif);
	wg_netif = nullptr;

	this->_is_initialized = false;
}

bool WireGuard::isUp(IPAddress& peerIP) {
	ip_addr_t peer_ip;
	err_t err;

	peerIP = IPAddress(0,0,0,0);
	if (!_is_initialized || (wireguard_peer_index == WIREGUARDIF_INVALID_INDEX)) {
		return false;
	}
	err = wireguardif_peer_is_up(wg_netif, wireguard_peer_index, &peer_ip, NULL);
	if (err != ERR_ARG) {
		peerIP = ip4_addr_get_u32(ip_2_ip4(&peer_ip));
	}
	return (err == ERR_OK);
}

void WireGuard::setDefaultIface() {
	// Set default interface to WG device.
	WG_MUTEX_LOCK();
	netif_set_default(wg_netif);
	WG_MUTEX_UNLOCK();
}
