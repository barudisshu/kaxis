/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.util

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.InetAddress
import java.net.NetworkInterface
import kotlin.test.assertContains

internal class NetworkInterfacesUtilTest {
  companion object {
    private val ARRAY_TYPE: Array<out InetAddress?> = arrayOfNulls(0)
  }

  @BeforeEach
  fun setUp() {
    System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES, "")
    System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES_EXCLUDE, "")
  }

  @Test
  fun testGetMtu() {
    val mtu = NetworkInterfacesUtil.anyMtu
    val mtu4 = NetworkInterfacesUtil.ipv4Mtu
    val mtu6 = NetworkInterfacesUtil.ipv6Mtu
    if (mtu4 < mtu6) {
      assertTrue(mtu in mtu4..mtu6)
    } else {
      assertTrue(mtu in mtu6..mtu4)
    }
  }

  @Test
  fun testIsAny() {
    val any4 = NetworkInterfacesUtil.anyIpv4
    val any6 = NetworkInterfacesUtil.anyIpv6
    assertTrue(any4 || any6)
  }

  @Test
  fun testGetNetworkInterfaces() {
    val networkInterfaces = NetworkInterfacesUtil.getNetworkInterfaces()
    assertFalse(networkInterfaces.isEmpty())
    assertEquals(networkInterfaces.size, HashSet(networkInterfaces).size)

    val first = networkInterfaces.iterator().next()
    val firstInterface = NetworkInterface.getByInetAddress(first).name.replace(".", "\\.")

    // filter networks by the name of the first interface
    System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES, firstInterface)
    val networkInterfaces2 = NetworkInterfacesUtil.getNetworkInterfaces()
    assertFalse(networkInterfaces2.isEmpty())
    assertTrue(networkInterfaces.containsAll(networkInterfaces2))
    assertContains(networkInterfaces2, first)

    // filter networks excluding the name of the first interface
    System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES, "")
    var exclude = NetworkInterfacesUtil.DEFAULT_COAP_NETWORK_INTERFACES_EXCLUDE
    exclude = exclude.substring(0, exclude.length - 1)
    exclude += "|$firstInterface)"
    System.setProperty(NetworkInterfacesUtil.COAP_NETWORK_INTERFACES_EXCLUDE, exclude)
    val networkInterface3 = NetworkInterfacesUtil.getNetworkInterfaces()
    assertFalse(networkInterface3.isEmpty())
    assertTrue(networkInterfaces.containsAll(networkInterface3))
    assertFalse(networkInterface3.contains(first))

    // total set of both filtered results
    val all = HashSet(networkInterfaces2)
    all.addAll(networkInterface3)
    assertEquals(all.size, networkInterfaces.size)
    assertTrue(networkInterfaces.containsAll(all))
    assertTrue(all.containsAll(networkInterfaces))
  }

  @Test
  fun testGetIpv6Scopes() {
    assertTrue(NetworkInterfacesUtil.anyIpv6)
    val networkInterfaces = NetworkInterfacesUtil.getNetworkInterfaces()
    assertFalse(networkInterfaces.isEmpty())
    val scopes = NetworkInterfacesUtil.ipv6Scopes
    assertFalse(scopes.isEmpty())
    val multicastInterface = NetworkInterfacesUtil.multicastInterface
    assertContains(scopes, multicastInterface?.name)
  }

  @Test
  fun testGetBroadcastIpv4() {
    assertTrue(NetworkInterfacesUtil.anyIpv4)
    val broadcast = NetworkInterfacesUtil.broadcastIpv4
    assertNotNull(broadcast)
    assertTrue(NetworkInterfacesUtil.isBroadcastAddress(broadcast))
  }

  @Test
  fun testGetMulticastInterface() {
    var multicast: InetAddress? = NetworkInterfacesUtil.multicastInterfaceIpv4
    if (multicast == null) {
      multicast = NetworkInterfacesUtil.multicastInterfaceIpv6
    }

    val multicastByAddress = NetworkInterface.getByInetAddress(multicast)
    val multicastInterface = NetworkInterfacesUtil.multicastInterface
    assertEquals(multicastByAddress, multicastInterface)
  }
}
