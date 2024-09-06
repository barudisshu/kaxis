/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.provider

import io.kaxis.ansi.Highlight
import org.bouncycastle.tls.*
import org.bouncycastle.util.Arrays
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.LinkedTransferQueue
import java.util.concurrent.TimeUnit

/**
 * A non-blocking udp datagram transport.
 * @author galudisu
 */
class UdpTransport(private val peer: Peer) : DatagramTransport {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(UdpTransport::class.java)
    private var mtu = 1500

    init {
      try {
        mtu = NetworkInterface.getByInetAddress(InetAddress.getByName(null)).mtu.coerceAtMost(mtu)
      } catch (e: SocketException) {
        LOGGER.warn("Socket status unknown from current interface.")
      } catch (e: UnknownHostException) {
        LOGGER.warn("Exception ${e.message} occurred while getting MTU from default interface.")
      }
    }

    private const val MIN_IP_OVERHEAD = 20
    private const val MAX_IP_OVERHEAD = MIN_IP_OVERHEAD + 64
    private const val UDP_OVERHEAD = 8

    private val RECV_BUFFER_SIZE = mtu - MIN_IP_OVERHEAD - UDP_OVERHEAD
    private val SEND_BUFFER_SIZE = mtu - MAX_IP_OVERHEAD - UDP_OVERHEAD
  }

  private val readQueue = LinkedTransferQueue<ByteArray>()

  /**
   * Since using non-blocking/event-driver design principle. The [[waitMillis]] is not cared which will cause thread interrupted.
   */
  override fun receive(
    buf: ByteArray?,
    off: Int,
    len: Int,
    waitMillis: Int,
  ): Int {
    try {
      val bytes = readQueue.poll(waitMillis.toLong(), TimeUnit.MILLISECONDS)
      if (bytes != null && buf != null) {
        if (TlsUtils.readUint8(bytes, off) == ContentType.handshake) {
          LOGGER.debug(
            "<------ Received handshake: {}{}{}",
            Highlight.CYAN,
            // 13 x 4 = 52(bytes)
            HandshakeType.getName(TlsUtils.readUint8(bytes, off + 13)),
            Highlight.RESET,
          )
        } else {
          LOGGER.debug(
            "<------ Receive polled: {}{}{}",
            Highlight.GREEN,
            ContentType.getName(TlsUtils.readUint8(bytes, off)),
            Highlight.RESET,
          )
        }

        val byteBuffer = ByteBuffer.wrap(bytes)
        byteBuffer.order(ByteOrder.BIG_ENDIAN)
        byteBuffer.rewind()
        // The copy solved the Mini len <= MTU issue.
        val byteToRead = byteBuffer.remaining().coerceAtMost(len)
        System.arraycopy(bytes, off, buf, 0, byteToRead)
        Arrays.fill(bytes, 0.toByte())

        return byteToRead
      }
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
    }

    return -1
  }

  @Throws(IOException::class)
  override fun send(
    buf: ByteArray?,
    off: Int,
    len: Int,
  ) {
    if (buf == null) return

    if (len > sendLimit) {
      /*
       * RFC 4347 4.1.1. "If the application attempts to send a record larger than the MTU,
       * the DTLS implementation SHOULD generate an error, thus avoiding sending a packet
       * which will be fragmented."
       */
      LOGGER.error("The record send reply to client side is larger than the MTU")
      throw TlsFatalAlert(AlertDescription.internal_error)
    } else {
      if (TlsUtils.readUint8(buf, off) == ContentType.handshake) {
        LOGGER.debug(
          "------> UDP transport Layer emit data handshake message: {}{}{}",
          Highlight.CYAN,
          HandshakeType.getName(TlsUtils.readUint8(buf, off + 13)),
          Highlight.RESET,
        )
      } else {
        LOGGER.debug(
          "------> UDP transport layer emit data content type: {}{}{}",
          Highlight.GREEN,
          ContentType.getName(TlsUtils.readUint8(buf, off)),
          Highlight.RESET,
        )
      }
      // Send messages to peer
      peer.emit(buf, off, len)
    }
  }

  override fun getReceiveLimit(): Int = RECV_BUFFER_SIZE

  override fun getSendLimit(): Int = SEND_BUFFER_SIZE

  override fun close() {
    synchronized(readQueue) {
      readQueue.clear()
    }
  }

  @Throws(InterruptedException::class)
  fun enqueue(buf: ByteArray) {
    readQueue.put(buf)
  }

  fun hasPackets(): Boolean {
    synchronized(readQueue) {
      return readQueue.isNotEmpty()
    }
  }
}
