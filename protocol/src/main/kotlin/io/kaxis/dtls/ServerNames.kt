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

import io.kaxis.util.DatagramReader
import io.kaxis.util.DatagramWriter
import io.kaxis.util.Utility

class ServerNames : MutableIterable<ServerName> {
  companion object {
    const val LIST_LENGTH_BITS = 16
    const val NAME_LENGTH_BITS = 16

    /**
     * Creates an empty server name list.
     * @return the new instance.
     */
    fun newInstance(): ServerNames = ServerNames()

    /**
     * Creates a new server name list from an initial server name.
     * @param serverName the server name to add.
     * @return the new instance.
     */
    fun newInstance(serverName: ServerName?): ServerNames {
      requireNotNull(serverName) { "server name must not be null" }
      return ServerNames(serverName)
    }

    /**
     * Creates a new server name list from an initial host name.
     * @param hostName the host name to add as [ServerName.NameType.HOST_NAME].
     * @return the new instance.
     */
    fun newInstance(hostName: String?): ServerNames {
      requireNotNull(hostName) { "host name must not be null" }
      return ServerNames(ServerName.from(ServerName.NameType.HOST_NAME, hostName.toByteArray(ServerName.CHARSET)))
    }

    /**
     * Checks, whether hostnames are "equal to" each other.
     * @param hostnameA first hostname to check
     * @param hostnameB second hostname to check
     * @return `true`, if the hostnames are equal ignoring the case, `false`, otherwise.
     */
    fun equalsIgnoreCase(
      hostnameA: String?,
      hostnameB: String?,
    ): Boolean {
      if (hostnameA == hostnameB) {
        return true
      } else if (hostnameA == null || hostnameB == null) {
        return false
      }
      return hostnameA.equals(hostnameB, true)
    }
  }

  private val names: MutableSet<ServerName> = linkedSetOf()

  private constructor()

  private constructor(serverName: ServerName?) : this() {
    plus(serverName)
  }

  /**
   * Adds a server name to this list.
   * @param serverName the server name to add.
   * @return this instance for command chaining.
   * @throws NullPointerException if serverName is `null`
   * @throws IllegalArgumentException if a serverName of the same type is already contained.
   */
  operator fun plus(serverName: ServerName?): ServerNames {
    requireNotNull(serverName) { "server name must not be null" }
    require(getServerName(serverName.type) == null) { "there is already a name of the given type" }
    names.add(serverName)
    return this
  }

  /**
   * Gets the number of bytes this server name list is encoded to. Includes the overall length itself.
   * @return [serverNamesLength] with the additional size of that encoded length.
   */
  val length: Int
    get() {
      return serverNamesLength + (LIST_LENGTH_BITS / Byte.SIZE_BITS)
    }

  /**
   * Gets the number of bytes this server names are encoded to.
   * @return the length in bytes.
   */
  val serverNamesLength: Int
    get() {
      var length = 0
      names.forEach { serverName ->
        length += 1 + (NAME_LENGTH_BITS / Byte.SIZE_BITS)
        length += serverName.length
      }
      return length
    }

  /**
   * Gets the number of names contained in this list.
   * @return the number of entries.
   */
  val size: Int
    get() = names.size

  /**
   * Gets the name value of a server name of a particular type.
   * @param type the name type.
   * @return the name or `null` if no name of the given type is part of the extension.
   */
  operator fun get(type: ServerName.NameType): ByteArray? {
    val serverName = getServerName(type)
    return serverName?.name
  }

  fun encode(writer: DatagramWriter) {
    writer.write(serverNamesLength, LIST_LENGTH_BITS) // server_names_list_length
    names.forEach { serverName ->
      writer.writeByte(serverName.type.code.toByte()) // name type
      writer.writeVarBytes(serverName.name, NAME_LENGTH_BITS)
    }
  }

  fun decode(reader: DatagramReader) {
    val listLengthBytes = reader.read(LIST_LENGTH_BITS)
    val rangeReader = reader.createRangeReader(listLengthBytes)
    while (rangeReader.bytesAvailable()) {
      when (val nameType = ServerName.NameType.fromCode(rangeReader.readNextByte().toInt())) {
        ServerName.NameType.HOST_NAME -> {
          val hostname = rangeReader.readVarBytes(NAME_LENGTH_BITS)
          plus(ServerName.from(nameType, hostname))
        }

        else -> throw IllegalArgumentException(
          "ServerNames: unknown name_type!",
          IllegalArgumentException(nameType.name),
        )
      }
    }
  }

  /**
   * Gets the server name of a particular type.
   * @param type the name type.
   * @return the server name or `null` if no server name of the given type is part of the extension.
   */
  fun getServerName(type: ServerName.NameType): ServerName? {
    names.forEach { serverName ->
      if (serverName.type == type) {
        return serverName
      }
    }
    return null
  }

  override fun iterator(): MutableIterator<ServerName> {
    return names.iterator()
  }

  fun toString(indent: Int): String {
    return StringBuilder().apply sb@{
      val indentation = Utility.indentation(indent + 1)
      this@sb.append(indentation).append("Server Names[").append(size).append(" entries")
      this@ServerNames.forEach { serverName ->
        this@sb.append(", '").append(serverName.nameAsString).append("' (").append(serverName.type).append(")")
      }
      this@sb.append("]")
    }.toString()
  }

  override fun toString(): String {
    return toString(0)
  }

  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    names.forEach { name ->
      result = prime * result + name.hashCode
    }
    return result
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    }
    if (other == null) {
      return false
    }
    if (other !is ServerNames) {
      return false
    }
    if (names.size != other.names.size) {
      return false
    }
    return names.containsAll(other.names)
  }
}
