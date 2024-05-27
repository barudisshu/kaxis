/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

@file:JvmName("NetworkInterfacesUtil")

package io.kaxis.util

import org.slf4j.LoggerFactory
import java.net.*
import java.net.NetworkInterface.getNetworkInterfaces
import java.util.*
import java.util.regex.Pattern

/**
 * Utility class for NetworkInterfaces. Determine MTU, IPv4, IPv6 support.
 *
 * Use environment "COAP_NETWORK_INTERFACES" to define a regular expression for
 * network interfaces to use, defaults to all. Use environment
 * "COAP_NETWORK_INTERFACES_EXCLUDES" to define a regular expression for network
 * interfaces to exclude from usage, defaults to commons virtual networks.
 *
 *
 */
object NetworkInterfacesUtil {
  private val LOGGER = LoggerFactory.getLogger(NetworkInterfacesUtil::class.java)

  /**
   * Maximum UDP MTU.
   */
  const val MAX_MTU: Int = 65535

  const val DEFAULT_MTU = 1500

  const val MIN_IP_OVERHEAD = 20

  const val MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64

  const val UDP_OVERHEAD = 8

  const val RECV_BUFFER_SIZE = DEFAULT_MTU - MIN_IP_OVERHEAD - UDP_OVERHEAD

  const val SEND_BUFFER_SIZE = DEFAULT_MTU - MAX_IP_OVERHEAD - UDP_OVERHEAD

  const val DEFAULT_IPV6_MTU = 1280

  const val DEFAULT_IPV4_MTU = 576

  @JvmField
  val COAP_NETWORK_INTERFACES = "COAP_NETWORK_INTERFACES"

  @JvmField
  val COAP_NETWORK_INTERFACES_EXCLUDE = "COAP_NETWORK_INTERFACES_EXCLUDE"

  @JvmField
  val DEFAULT_COAP_NETWORK_INTERFACES_EXCLUDE =
    "(vxlan\\.calico|cali[0123456789abcdef]{10,}|cilium_\\w+|lxc[0123456789abcdef]{12,}|virbr\\d+|docker\\d+)"

  private val DEFAULT_EXCLUDE = Pattern.compile(DEFAULT_COAP_NETWORK_INTERFACES_EXCLUDE)

  private val IPV6_SCOPE = "^([0-9a-fA-F:]+)(%\\w+)?$".toPattern()

  private var anyMtu0: Int = 0

  /**
   * MTU for any interface. Determine the smallest MTU of all network interfaces.
   */
  val anyMtu: Int
    get() {
      initialize()
      return anyMtu0
    }

  private var ipv4Mtu0: Int = 0

  /**
   * MTU for IPv4 interface. Determine the smallest MTU of all IPv4 network interfaces.
   */
  val ipv4Mtu: Int
    get() {
      initialize()
      return ipv4Mtu0
    }

  private var ipv6Mtu0: Int = 0

  /**
   * MTU for IPv6 interface. Determine the smallest MTU of all IPv6 network interfaces.
   */
  val ipv6Mtu: Int
    get() {
      initialize()
      return ipv6Mtu0
    }

  private var anyIpv40: Boolean = false

  /**
   * One of any interfaces supports IPv4.
   * @return `true`, if any interface supports IPv4, `false`, otherwise.
   */
  val anyIpv4: Boolean
    get() {
      initialize()
      return anyIpv40
    }

  private var anyIpv60: Boolean = false

  /**
   * One of any interfaces supports IPv6.
   * @return `true`, if any interface supports IPv6, `false`, otherwise.
   */
  val anyIpv6: Boolean
    get() {
      initialize()
      return anyIpv60
    }

  private var broadcastIpv40: Inet4Address? = null

  /**
   * A IPv4 broadcast address on a multicast supporting network interface, if available.
   */
  val broadcastIpv4: Inet4Address?
    get() {
      initialize()
      return broadcastIpv40
    }

  private var multicastInterfaceIpv40: Inet4Address? = null

  /**
   * A IPv4 address of a multicast supporting network interface, if available.
   */
  val multicastInterfaceIpv4: Inet4Address?
    get() {
      initialize()
      return multicastInterfaceIpv40
    }

  private var multicastInterfaceIpv60: Inet6Address? = null

  /**
   * A IPv6 address of a multicast supporting network interface, if available.
   */
  val multicastInterfaceIpv6: Inet6Address?
    get() {
      initialize()
      return multicastInterfaceIpv60
    }

  private var multicastInterface0: NetworkInterface? = null

  /**
   * A multicast supporting [NetworkInterface]s.
   */
  val multicastInterface: NetworkInterface?
    get() {
      initialize()
      return multicastInterface0
    }

  /**
   * Set of detected broadcast addresses.
   */
  val broadcastAddresses: MutableSet<InetAddress> = mutableSetOf()

  /**
   * Check, if address is broadcast address of one of the network interfaces.
   *
   * @param address address to check
   * @return `true`, if address is broadcast address of one of the network interfaces, `false`, otherwise.
   */
  fun isBroadcastAddress(address: InetAddress?): Boolean {
    initialize()
    return broadcastAddresses.contains(address)
  }

  fun isMultiAddress(address: InetAddress?): Boolean {
    initialize()
    return address != null && (address.isMulticastAddress || broadcastAddresses.contains(address))
  }

  /**
   * Check, if both provided addresses are equal.
   *
   * @param address1 address 1. May be `null`, if not available.
   * @param address2 address 2. May be `null`, if not available.
   *
   * @return `true`, if both addresses are equal, `false`, if not.
   */
  fun equals(
    address1: InetAddress?,
    address2: InetAddress?,
  ): Boolean {
    return address1 == address2 || (address1 != null && address1 == address2)
  }

  /**
   * Check, if both provided socket addresses are equal.
   *
   * @param address1 address 1. May be `null`, if not available.
   * @param address2 address 2. May be `null`, if not available.
   *
   * @return `true`, if both addresses are equal, `false`, if not.
   */
  fun equals(
    address1: SocketAddress?,
    address2: SocketAddress?,
  ): Boolean {
    return address1 == address2 || (address1 != null && address1 == address2)
  }

  private val ipv6Scopes0: MutableSet<String> = mutableSetOf()

  /**
   * Set of available IPv6 scopes. Only scopes with multicast support are included.
   */
  val ipv6Scopes: MutableSet<String>
    get() {
      initialize()
      return Collections.unmodifiableSet(ipv6Scopes0)
    }

  /**
   * Get collection of available local inet addresses of network interfaces.
   *
   * Applies environment "COAP_NETWORK_INTERFACES" to define a regular
   * expression for network interfaces to use, defaults to all. And
   * environment "COAP_NETWORK_INTERFACES_EXCLUDES" to define a regular
   * expression for network interfaces to exclude from usage, defaults to
   * common virtual networks.
   *
   * @return collection of loal inet addresses.
   */
  val networkInterfaces: Collection<InetAddress>
    get() = getNetworkInterfaces()

  class Filter : Enumeration<NetworkInterface> {
    private var nextInterface: NetworkInterface? = null

    private val source: Enumeration<NetworkInterface>

    private val filter: Pattern?

    private val excludeFilter: Pattern?

    constructor(source: Enumeration<NetworkInterface>) {
      this.source = source
      var filter: Pattern? = null
      var excludeFilter: Pattern? = null
      val regex = Utility.getConfiguration(COAP_NETWORK_INTERFACES)
      val excludeRegex = Utility.getConfiguration(COAP_NETWORK_INTERFACES_EXCLUDE)
      if (!regex.isNullOrEmpty()) {
        filter = Pattern.compile(regex)
      } else if (excludeRegex.isNullOrEmpty()) {
        excludeFilter = DEFAULT_EXCLUDE
      }
      if (!excludeRegex.isNullOrEmpty()) {
        excludeFilter = Pattern.compile(excludeRegex)
      }
      this.filter = filter
      this.excludeFilter = excludeFilter
      next()
    }

    override fun hasMoreElements(): Boolean {
      return nextInterface != null
    }

    override fun nextElement(): NetworkInterface? {
      val result = nextInterface
      next()
      return result
    }

    private fun next() {
      nextInterface = null
      while (source.hasMoreElements()) {
        val iface = source.nextElement() ?: continue
        val name = iface.name
        try {
          if (iface.isUp && (filter == null || filter.matcher(name).matches())) {
            if (excludeFilter == null || !excludeFilter.matcher(name).matches()) {
              nextInterface = iface
              break
            }
          }
        } catch (e: SocketException) {
          // NOSONAR
        }
        LOGGER.debug("skip {}", name)
      }
    }
  }

  /**
   * Filter inet-addresses.
   *
   * @see [getNetworkInterfaces]
   */
  fun interface InetAddressFilter {
    /**
     * Filter return inet-addresses.
     * @param addr inet-address to filter
     * @return `true`, to add inet-address, `false`, to skip.
     */
    fun matches(addr: InetAddress): Boolean
  }

  /**
   * Simple inet address filter. Filters inet addresses based on local and external addresses, on IPv4 and IPv6,
   * and on patterns.
   *
   * @see [getNetworkInterfaces]
   */
  class SimpleInetAddressFilter : InetAddressFilter {
    private val tag: String
    private val externalAddresses: Boolean
    private val loopbackAddresses: Boolean
    private val ipv4: Boolean
    private val ipv6: Boolean
    private val patterns: Array<out String>

    constructor(
      tag: String,
      externalAddresses: Boolean,
      localAddresses: Boolean,
      ipv4: Boolean,
      ipv6: Boolean,
      vararg patterns: String,
    ) {
      require(
        externalAddresses || localAddresses,
      ) { "$tag: at least one of external or local addresses must must be true" }
      require(ipv4 || ipv6) { "$tag: at least one of IPv4 or IPv6 must be true" }
      this.tag = tag
      this.externalAddresses = externalAddresses
      this.loopbackAddresses = localAddresses
      this.ipv4 = ipv4
      this.ipv6 = ipv6
      this.patterns = patterns
    }

    @Suppress("kotlin:S3776")
    override fun matches(addr: InetAddress): Boolean {
      if (addr.isLoopbackAddress || addr.isLinkLocalAddress) {
        if (!loopbackAddresses) {
          var scope = "???"
          if (addr.isLoopbackAddress) {
            scope = "lo"
          } else if (addr.isLinkLocalAddress) {
            scope = "link"
          }
          LOGGER.info("{}skip local {} ({})", tag, addr, scope)
          return false
        }
      } else if (!externalAddresses) {
        LOGGER.info("{}skip external {}", tag, addr)
        return false
      }
      if (addr is Inet4Address) {
        if (!ipv4) {
          LOGGER.info("{}skip IPv4 {}", tag, addr)
          return false
        }
      } else if (addr is Inet6Address) {
        if (!ipv6) {
          LOGGER.info("{}skip IPv6 {}", tag, addr)
          return false
        }
      }
      if (patterns.isEmpty()) {
        var found = false
        var name = addr.hostAddress
        patterns.forEach { filter ->
          if (name.matches(filter.toRegex())) {
            found = true
            return@forEach
          }
        }
        if (!found && addr is Inet6Address) {
          val matcher = IPV6_SCOPE.matcher(name)
          if (matcher.matches()) {
            // apply filter also on interface name
            name = matcher.group(1) + "%" + (addr.scopedInterface.name)
            patterns.forEach { filter ->
              if (name.matches(filter.toRegex())) {
                found = true
                return@forEach
              }
            }
          }
        }
        if (!found) {
          return false
        }
      }
      return true
    }
  }

  @Suppress("kotlin:S3776")
  @Synchronized
  private fun initialize() {
    if (anyMtu0 == 0) {
      clear()
      var mtu = MAX_MTU
      var ipv4mtu = MAX_MTU
      var ipv6mtu = MAX_MTU

      try {
        var interfaces: Enumeration<NetworkInterface> =
          NetworkInterface.getNetworkInterfaces() ?: throw SocketException("Network interfaces not available!")

        interfaces = Filter(interfaces)
        while (interfaces.hasMoreElements()) {
          val iface = interfaces.nextElement()
          if (iface != null) {
            if (!iface.isLoopback) {
              val ifaceMtu = iface.mtu
              if (ifaceMtu in 1..<mtu) {
                mtu = ifaceMtu
              }
              if (iface.supportsMulticast()) {
                val inetAddresses = iface.inetAddresses
                while (inetAddresses.hasMoreElements()) {
                  val address = inetAddresses.nextElement()
                  if (address is Inet6Address) {
                    if (address.scopeId > 0) {
                      ipv6Scopes0.add(iface.name)
                    }
                  }
                }
              }
              if (iface.supportsMulticast() &&
                (multicastInterfaceIpv40 == null || multicastInterfaceIpv60 == null || broadcastIpv40 == null)
              ) {
                var broad4: Inet4Address? = null
                var link4: Inet4Address? = null
                var site4: Inet4Address? = null
                var link6: Inet6Address? = null
                var site6: Inet6Address? = null
                // find the network interface with the most
                // multicast/broadcast possibilities
                var countMultiFeatures = 0
                if (broadcastIpv40 != null) {
                  --countMultiFeatures
                }
                if (multicastInterfaceIpv40 != null) {
                  --countMultiFeatures
                }
                if (multicastInterfaceIpv60 != null) {
                  --countMultiFeatures
                }
                val inetAddresses = iface.inetAddresses
                while (inetAddresses.hasMoreElements()) {
                  val address = inetAddresses.nextElement()
                  if (address is Inet4Address) {
                    anyIpv40 = true
                    if (ifaceMtu in 1..<ipv4mtu) {
                      ipv4mtu = ifaceMtu
                    }
                    if (site4 == null) {
                      if (address.isSiteLocalAddress) {
                        site4 = address
                      } else if (link4 == null && address.isLinkLocalAddress) {
                        link4 = address
                      }
                    }
                  } else if (address is Inet6Address) {
                    anyIpv60 = true
                    if (ifaceMtu in 1..<ipv6mtu) {
                      ipv6mtu = ifaceMtu
                    }
                    if (site6 == null) {
                      if (address.isSiteLocalAddress) {
                        site6 = address
                      } else if (link4 == null && address.isLinkLocalAddress) {
                        link6 = address
                      }
                    }
                  }
                }
                iface.interfaceAddresses.forEach { interfaceAddress ->
                  val broadcast = interfaceAddress.broadcast
                  if (broadcast != null && !broadcast.isAnyLocalAddress) {
                    val address = interfaceAddress.address
                    if (address != null && address != broadcast) {
                      broadcastAddresses.add(broadcast)
                      LOGGER.debug("Found broadcast address {} - {}.", broadcast, iface.name)
                      if (broad4 == null) {
                        broad4 = broadcast as Inet4Address
                        ++countMultiFeatures
                      }
                    }
                  }
                }
                if (link4 != null || site4 != null) {
                  ++countMultiFeatures
                }
                if (link6 != null || site6 != null) {
                  ++countMultiFeatures
                }
                if (countMultiFeatures > 0) {
                  // more multicast/broadcast possibilities as before
                  multicastInterface0 = iface
                  broadcastIpv40 = broad4
                  multicastInterfaceIpv40 = site4 ?: link4
                  multicastInterfaceIpv60 = site6 ?: link6
                }
              } else {
                val inetAddresses = iface.inetAddresses
                while (inetAddresses.hasMoreElements()) {
                  val address = inetAddresses.nextElement()
                  if (address is Inet4Address) {
                    anyIpv40 = true
                    if (ifaceMtu in 1..<ipv4mtu) {
                      ipv4mtu = ifaceMtu
                    }
                  } else if (address is Inet6Address) {
                    anyIpv60 = true
                    if (ifaceMtu in 1..<ipv6mtu) {
                      ipv6mtu = ifaceMtu
                    }
                  }
                }
              }
            }
          }
        }
      } catch (ex: SocketException) {
        LOGGER.warn("discover the <any> interface failed!", ex)
        anyIpv40 = true
        anyIpv60 = true
      }

      if (broadcastAddresses.isEmpty()) {
        LOGGER.info("no broadcast address found!")
      }
      if (ipv4mtu == MAX_MTU) {
        ipv4mtu = DEFAULT_IPV4_MTU
      }
      if (ipv6mtu == MAX_MTU) {
        ipv6mtu = DEFAULT_IPV6_MTU
      }
      if (mtu == MAX_MTU) {
        mtu = ipv4mtu.coerceAtMost(ipv6mtu)
      }
      ipv4Mtu0 = ipv4mtu
      ipv6Mtu0 = ipv6mtu
      anyMtu0 = mtu
    }
  }

  /**
   * Clear discovered network parameters. Intended to be called in changing network environments to
   * (re-)discover the network's parameters.
   */
  private fun clear() {
    anyMtu0 = 0
    ipv4Mtu0 = 0
    ipv6Mtu0 = 0
    anyIpv40 = false
    anyIpv60 = false
    ipv6Scopes0.clear()
    broadcastAddresses.clear()
    broadcastIpv40 = null
    multicastInterfaceIpv40 = null
    multicastInterfaceIpv60 = null
    multicastInterface0 = null
  }

  /**
   * Get collection of available local inet addresses of network interfaces.
   *
   * Applies environment "COAP_NETWORK_INTERFACES" to define a regular
   * expression for network interfaces to use, defaults to all. And
   * environment "COAP_NETWORK_INTERFACES_EXCLUDES" to define a regular
   * expression for network interfaces to exclude from usage, defaults to
   * common virtual networks.
   *
   * @param filter custom filter for inet addresses
   * @return collection of local inet addresses
   */
  fun getNetworkInterfaces(filter: InetAddressFilter? = null): Collection<InetAddress> {
    val interfaces: MutableList<InetAddress> = mutableListOf()
    try {
      var nets: Enumeration<NetworkInterface> =
        NetworkInterface.getNetworkInterfaces() ?: throw SocketException("Network interfaces not available!")
      nets = Filter(nets)
      while (nets.hasMoreElements()) {
        val networkInterface = nets.nextElement()
        if (networkInterface != null) {
          LOGGER.debug("NetIntf: {}", networkInterface.displayName)
          val inetAddresses = networkInterface.inetAddresses
          while (inetAddresses.hasMoreElements()) {
            val address = inetAddresses.nextElement()
            if (filter == null || filter.matches(address)) {
              interfaces.add(address)
              LOGGER.debug("   Addr: {}", address)
            } else {
              LOGGER.debug("  Addr: {}", address)
            }
          }
        }
      }
    } catch (e: SocketException) {
      LOGGER.error("could not fetch all interface addresses", e)
    }
    return interfaces
  }
}
