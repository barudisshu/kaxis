/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.provider

import io.mockk.every
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import io.mockk.verify
import org.bouncycastle.tls.ContentType
import org.bouncycastle.tls.TlsFatalAlert
import org.bouncycastle.tls.TlsUtils
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentMatchers.anyInt
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

@ExtendWith(MockKExtension::class)
internal class UdpTransportTest {
  private lateinit var udpTransport: UdpTransport

  @RelaxedMockK
  private lateinit var peer: Peer

  @BeforeEach
  fun setUp() {
    every { peer.emit(any<ByteArray>(), anyInt(), anyInt()) } returns Unit
    udpTransport = UdpTransport(peer)
  }

  @Test
  fun `trigger receive msg`() {
    val heartbeat = ByteArray(1)
    TlsUtils.writeUint8(ContentType.heartbeat, heartbeat, 0)
    udpTransport.enqueue(heartbeat)

    assertTrue { udpTransport.hasPackets() }

    assertTrue { udpTransport.receiveLimit > 0 }
    assertTrue { udpTransport.sendLimit > 0 }

    // receive
    var received = udpTransport.receive(heartbeat, 0, 1, 10)
    assertNotEquals(-1, received)

    // empty
    received = udpTransport.receive(heartbeat, 0, 1, 0)
    assertEquals(-1, received)

    udpTransport.send(heartbeat, 0, 1)
    verify { peer.emit(any<ByteArray>(), 0, 1) }

    assertThrows<TlsFatalAlert> { udpTransport.send(heartbeat, 0, 1500 - 20 - 64 - 8 + 1) }

    udpTransport.close()
    assertFalse { udpTransport.hasPackets() }
  }
}
