/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.dtls

import io.kaxis.util.NetworkInterfacesUtil

const val DEFAULT_IPV6_MTU = NetworkInterfacesUtil.DEFAULT_IPV6_MTU

const val DEFAULT_IPV4_MTU = NetworkInterfacesUtil.DEFAULT_IPV4_MTU

const val DEFAULT_ETH_MTU = 1500

const val IPV4_HEADER_LENGTH = (
  8 + // bytes UDP headers
    20 + // bytes IP headers
    36 // bytes optional IP options
)

const val IPV6_HEADER_LENGTH = 128 // 1280 - 1152 bytes, assumption of RFC 7252, Section 4.6.
