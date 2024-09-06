/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
