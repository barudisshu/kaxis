/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis

import io.kaxis.ansi.Highlight
import io.kaxis.provider.protocols.AbstractDtlsClient
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.tls.*
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

class ManuallyTest {
  companion object {
    @JvmStatic
    fun main(args: Array<String>) {
      val client = ShardingDtlsClient()
      val dtls = openDtlsConnection(client)

      // Send and hopefully receive a packet back
      var counter = 0
      while (counter < 10) {
        val request = "Ack-0$counter".toByteArray()
        dtls.send(request, 0, request.size)
        println(
          "\n[Client] Send ${Highlight.RED}________> \n${Highlight.GREEN_BACKGROUND}${String(
            request,
          )}${Highlight.RESET}",
        )

        val response = ByteArray(dtls.receiveLimit)
        val received = dtls.receive(response, 0, response.size, 5_000)
        if (received > 0) {
          println(
            "\n[Client] Receive ${Highlight.GREEN} <____ \n${Highlight.RED_BACKGROUND}${
              String(
                response,
                0,
                received,
              )
            }${Highlight.RESET}",
          )
        }
        TimeUnit.SECONDS.sleep(2L)
        counter--
      }
    }

    @Throws(IOException::class)
    private fun openDtlsConnection(client: TlsClient): DTLSTransport {
      val socket = DatagramSocket()
      socket.connect(InetSocketAddress("127.0.0.1", 5684))
      val transport = UDPTransport(socket, 1500)
      val protocol = DTLSClientProtocol()
      return protocol.connect(client, transport)
    }

    internal class ShardingDtlsClient : AbstractDtlsClient() {
      override fun getClientCaCert(): Certificate {
        val ca =
          """
          -----BEGIN CERTIFICATE-----
          MIIEITCCAwmgAwIBAgIUZ1EuCh2yX8hJoJJwZfOS/9zHNwgwDQYJKoZIhvcNAQEL
          BQAwgZ4xCzAJBgNVBAYTAmNuMRIwEAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcM
          CUd1YW5nemhvdTEXMBUGA1UECgwORXJpY3Nzb24sIEluYy4xETAPBgNVBAsMCGVy
          aWNzc29uMRUwEwYDVQQDDAxlcmljc3Nvbi5jb20xJDAiBgkqhkiG9w0BCQEWFWdh
          bHVkaXN1QGVyaWNzc29uLmNvbTAgFw0yMjAzMTkwNjE5NDNaGA8zMDIxMDcyMDA2
          MTk0M1owgZ4xCzAJBgNVBAYTAmNuMRIwEAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNV
          BAcMCUd1YW5nemhvdTEXMBUGA1UECgwORXJpY3Nzb24sIEluYy4xETAPBgNVBAsM
          CGVyaWNzc29uMRUwEwYDVQQDDAxlcmljc3Nvbi5jb20xJDAiBgkqhkiG9w0BCQEW
          FWdhbHVkaXN1QGVyaWNzc29uLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
          AQoCggEBALGeNjWoqFQPPyc1BiPIJ54EM6A3blnrA5wZpB7FRcx1rNqep5IjIs/0
          xeOGCDRMtLuH5eyw1vOfvEHvSEDijZkOJY9ZiQFBdI3YVdN7BhUc7CFF13jrsgnV
          H+vbJrvppEphJPRoaEdruDUdRXptBekV7kiW5RHT4lLGtBJ5/dhpzK96+tT1j4Ci
          egCB+PqGVWbekaD/qSfVWaxQPcCp3xCM2tKqjLYQpkBcDAgKq5XxIKh2IASgPUcu
          Bmn9N+tMlWzaJvtr4qsp6AIHReHLXEp87+tX0sXiOSdeSZ5Wsi37PBZZifnEoNV1
          /EHqQi7M3VYKnJ+NXGyu+gUid/2sR8MCAwEAAaNTMFEwHQYDVR0OBBYEFClq8K9J
          LCXDbnn0PY+Xxj4emPifMB8GA1UdIwQYMBaAFClq8K9JLCXDbnn0PY+Xxj4emPif
          MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADJoU2BTW09/AZV/
          1QTc/HIZpKOFpJ0lLa/A0PF5aPBT9wvZWSQD8NTF6smVLM7soeI//j5e3rhLOV4E
          Q9qGgyGSGwtL802sXrw2JfeUu/6Izsz8t2zkQyOd91UDC3urgWruOLVUPghXgnQi
          OR7D84zWkCejRJT+GfFOQdyekrSHgPp2UJeakVILIChtb/d5pjee335SaoE2QhzE
          6p+b5YxzXct2QPJt+ojxgiPKh4LtntcL9/UQkBU93sw1h4s7ZrLcy0FU/NBtwkZA
          Pm6AajU2ZfsIUSu2YTmFj9i/XhjrrkS3hl3IX2+xjXtRax+qJbK+Hdln//6c1N4l
          9hqcK70=
          -----END CERTIFICATE-----

          """.trimIndent()
        return ca.asCertificate(crypto as BcTlsCrypto)
      }

      override fun getClientPrivateKey(): AsymmetricKeyParameter {
        val key =
          """
          -----BEGIN PRIVATE KEY-----
          MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCr7oyu/uOV1aZf
          MJk3S6nNGo0uyb0ZBts6sRsKesNAGS8Nv00gA74LCYVIDddBo/pOfivwj/3StFAw
          b2htF8J7+R1NDPweLagwUI4KYUpSb6yyfjkfZvnUdACM+sSqKeNjKQoEuOxcxgkW
          4WTypFmgtnYUOK1hu14eR5i0+fgDHTTxuqmxB4uhz2CYvIkW0GOjsx2hq5CKHMfK
          OuaEsU5zd1NWd16KW4kDm/pdzGgoN2chRvfnJWF4o98QnsDeXvo6U4RLOBYR9GdS
          OnlQQvXdrjLT1fBYjYnmo26bi9kDHsahifVvwNIV7wXBOkZ0cJwmqHPb49CL1Jfj
          RKhLoQFzAgMBAAECggEBAJITRmHz22bVM9pSTwrE9Up2kZc7/baCtcaC7KeVr8gI
          3Yp/i0Z1B4UXHK8gW0/Awwznc+uaWxwm6K6OKRnvAuUTvUpWiuoU/n22I0g8asnp
          ab/pMB02/3H68PDWqjqtBi2ck495khAsjVJsQ7lH24KJI3+AvAZ6C7gMOnkgnA//
          3xTiVXXbBC6xPEi7u1OUAeLnVKosOpXzxJQQXrODWwqvLhMW1NdTPUChREWAxBcJ
          poDDP9dQipfyygiHDmaIdxzz3OhSj4r7sc2lnWum90LhZlvjT0Ga0LrPnuUJUR1A
          OEcaWuIS8nSnFjWzb751ZqW4Tqj6o32jRcP/X46ULTkCgYEA0/GnG/XMoVjBx2A+
          fJ8rqR3ull2/tBn5K3LlaEwTM5GjDBcdSLBHOLduhwZ/vD3dzxttud344Vk2wpmi
          P+obaQ5j2zHXDq2Wzy+9pOHOqA6vo3/IZEQSSDK5MK4xPwOnec80Wd72e40/sJDv
          x4OZi5KUDfCTRnV/2qxbEPb7HDUCgYEAz6uy8AzyLkDYLcwmQJbRgdykrsLaVgj3
          h+j8m7412Mu5DDen6gbSsG8zJuzQWpNEhmqqlAzSlKdJ5xgcBnwUBSdhSpSX0b6a
          GsGPBuFBTGEhmOPaqih0BLnugoVG0mh4MIkcHVFOp7FjxFZIYi22Pxi5zOB/6BDd
          k4DwJj5FzAcCgYAnQ3RO1LllBplXgzfwRFiFSvtBNfrmtY0YhH+FU9qWyhsniTyu
          k6GOG0VJlGWjjN6DmLQ6I6oQrUNcx7NsHcWYL8dF+zS5DmWK2nBKlF6Beb8GDg0k
          rguo/mSaZRrQbq/e/AjZwVluSBuNbTxOfM28Mppk/rV57xiRfS6dtPOOJQKBgA24
          gGgP0uhvbFkKRfS6gjkcRN0vDpHkocYfBKGdnZ0nSKCgBL4XmVAC6NRHjTSOylY/
          Men6NuePbfiQxTlAdWopwenVi3pWJ4RhCXwg4dmUCU46r7XSWmf9iN6iw50fPeGn
          DW56csHtnHPaZ4nlD0d38L6yjoDcrGcUe8lrD919AoGBALQBftbU+O8jHPIwqPwh
          X+ENcCQ99V8ENPYMHxAGROdLvrRkjKKkcRXlnSETxY7GTr6C77gSj91t5YHbiWx5
          TMyA41N0Wv0XMeM9uL8OJIjvT5TxNY77V0/xXwOLqhD8tq3DrFlTB66gGCEMIm+4
          5hHgXjU7HJulkdagL08eAblj
          -----END PRIVATE KEY-----

          """.trimIndent()
        return key.asAsymmetricKeyParameter()
      }

      override fun getClientCert(): Certificate {
        val x509 =
          """
          -----BEGIN CERTIFICATE-----
          MIIDuzCCAqMCAQEwDQYJKoZIhvcNAQELBQAwgZ4xCzAJBgNVBAYTAmNuMRIwEAYD
          VQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwORXJp
          Y3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRUwEwYDVQQDDAxlcmljc3Nv
          bi5jb20xJDAiBgkqhkiG9w0BCQEWFWdhbHVkaXN1QGVyaWNzc29uLmNvbTAgFw0y
          MjAzMTkwNjE5NDRaGA8zMDIxMDcyMDA2MTk0NFowgaUxCzAJBgNVBAYTAmNuMRIw
          EAYDVQQIDAlHdWFuZ2RvbmcxEjAQBgNVBAcMCUd1YW5nemhvdTEXMBUGA1UECgwO
          RXJpY3Nzb24sIEluYy4xETAPBgNVBAsMCGVyaWNzc29uMRwwGgYDVQQDDBNjbGll
          bnQuZXJpY3Nzb24uY29tMSQwIgYJKoZIhvcNAQkBFhVnYWx1ZGlzdUBlcmljc3Nv
          bi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr7oyu/uOV1aZf
          MJk3S6nNGo0uyb0ZBts6sRsKesNAGS8Nv00gA74LCYVIDddBo/pOfivwj/3StFAw
          b2htF8J7+R1NDPweLagwUI4KYUpSb6yyfjkfZvnUdACM+sSqKeNjKQoEuOxcxgkW
          4WTypFmgtnYUOK1hu14eR5i0+fgDHTTxuqmxB4uhz2CYvIkW0GOjsx2hq5CKHMfK
          OuaEsU5zd1NWd16KW4kDm/pdzGgoN2chRvfnJWF4o98QnsDeXvo6U4RLOBYR9GdS
          OnlQQvXdrjLT1fBYjYnmo26bi9kDHsahifVvwNIV7wXBOkZ0cJwmqHPb49CL1Jfj
          RKhLoQFzAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADyS/em384BLk3WsrLjTkfLg
          QN9C4mjgEJLU+LPNBAImnb7ouCc3Y4RQ+nM8uFqirPMUjEdjQCf7iz+vQa69i5S+
          ZfMo0XvOmO9mFia0MF2HvAVMbBO/UYL855w8R8Lu3TasUd0YKilpvewMcjaqFOzQ
          jo0v5pE3pdQXuXL68z7fTsEnxjSi94MFcjtNITiLOi4ie2KoHz5qJGAtV4aS0Yvx
          HDXESKH23ci2WUJAzR7PKbVfDc0mcTujiW0XB5Xc9A5mWPhvcxfbRQr4QjX3Z2RI
          0MG0F/WkbUKGoGTSWGhT69bqbEFimzTz+XaqUj5gxU8k5/YyKsh0dEge310jb7c=
          -----END CERTIFICATE-----
          """.trimIndent()
        return x509.asCertificate(crypto as BcTlsCrypto)
      }
    }
  }
}
