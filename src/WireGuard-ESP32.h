/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */
#pragma once
#include <IPAddress.h>

class WireGuard
{
private:
    bool _is_initialized = false;
public:
    bool begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    bool begin(const IPAddress& localIP, const IPAddress& Subnet, const IPAddress& Gateway, const char* privateKey, const IPAddress& DNS, uint16_t mtu);
    bool addPeer(const char* address, uint16_t port, const char* publicKey, const char* preSharedKey, const IPAddress& allowedAddr, const IPAddress& allowedMask, uint16_t keep_alive);
    bool begin(const IPAddress& localIP, const char* privateKey, const char* remotePeerAddress, const char* remotePeerPublicKey, uint16_t remotePeerPort);
    void end();
    bool is_initialized() const { return this->_is_initialized; }
    bool isUp(IPAddress& peerIP);
    void setDefaultIface();
};
