/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */
package io.kaxis.dtls;

import static org.junit.jupiter.api.Assertions.assertFalse;

import io.kaxis.JceProvider;
import io.kaxis.dtls.cipher.XECDHECryptography;
import io.kaxis.dtls.message.HandshakeMessage;
import io.kaxis.dtls.message.handshake.GenericHandshakeMessage;
import io.kaxis.dtls.message.handshake.HandshakeParameter;
import io.kaxis.exception.HandshakeException;
import io.kaxis.util.ClockUtil;
import io.kaxis.util.DatagramReader;
import io.kaxis.util.DatagramWriter;
import io.kaxis.util.Utility;
import io.kaxis.JceProvider;
import io.kaxis.dtls.cipher.XECDHECryptography;
import io.kaxis.dtls.message.HandshakeMessage;
import io.kaxis.dtls.message.handshake.GenericHandshakeMessage;
import io.kaxis.dtls.message.handshake.HandshakeParameter;
import io.kaxis.exception.HandshakeException;
import io.kaxis.util.ClockUtil;
import io.kaxis.util.DatagramReader;
import io.kaxis.util.DatagramWriter;
import io.kaxis.util.Utility;

import java.util.List;
import javax.net.ssl.X509KeyManager;

public final class DtlsTestTools extends TestCertificatesTools {

  public static final int DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS;

  static {
    Long delay = Utility.getConfigurationLong("DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS");
    DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS = delay == null ? 0 : delay.intValue();
  }

  private DtlsTestTools() {}

  public static X509KeyManager getDtlsServerKeyManager() {
    X509KeyManager keyManager = null;
    if (XECDHECryptography.SupportedGroup.X25519.isUsable()
        && JceProvider.isSupported(JceProvider.ED25519)) {
      keyManager = TestCertificatesTools.getServerEdDsaKeyManager();
    }
    if (keyManager == null) {
      keyManager = TestCertificatesTools.getServerKeyManager();
    }
    return keyManager;
  }

  public static Record getRecordForMessage(int epoch, int seqNo, DTLSMessage msg) {
    byte[] dtlsRecord =
        newDTLSRecord(msg.getContentType().getCode(), epoch, seqNo, msg.toByteArray());
    List<Record> list = DtlsTestTools.fromByteArray(dtlsRecord, null, ClockUtil.nanoRealtime());
    assertFalse(list.isEmpty(), "Should be able to deserialize DTLS Record from byte array");
    return list.get(0);
  }

  public static byte[] newDTLSRecord(
    int typeCode, int epoch, long sequenceNo, byte[] fragment) {
    return newDTLSRecord(typeCode, ProtocolVersion.VERSION_DTLS_1_2, epoch, sequenceNo, fragment);
  }

  public static byte[] newDTLSRecord(
    int typeCode, ProtocolVersion protocolVer, int epoch, long sequenceNo, byte[] fragment) {

    // the record header contains a type code, version, epoch, sequenceNo, length
    DatagramWriter writer = new DatagramWriter();
    writer.write(typeCode, 8);
    writer.write(protocolVer.getMajor(), 8);
    writer.write(protocolVer.getMinor(), 8);
    writer.write(epoch, 16);
    writer.writeLong(sequenceNo, 48);
    writer.write(fragment.length, 16);
    writer.writeBytes(fragment);
    return writer.toByteArray();
  }

  public static byte[] newClientCertificateTypesExtension(int... types) {
    DatagramWriter writer = new DatagramWriter();
    writer.write(types.length, 8);
    for (int type : types) {
      writer.write(type, 8);
    }
    return newHelloExtension(19, writer.toByteArray());
  }

  public static byte[] newServerCertificateTypesExtension(int... types) {
    DatagramWriter writer = new DatagramWriter();
    writer.write(types.length, 8);
    for (int type : types) {
      writer.write(type, 8);
    }
    return newHelloExtension(20, writer.toByteArray());
  }

  public static byte[] newSupportedEllipticCurvesExtension(int... curveIds) {
    DatagramWriter writer = new DatagramWriter();
    writer.write(curveIds.length * 2, 16);
    for (int type : curveIds) {
      writer.write(type, 16);
    }
    return newHelloExtension(10, writer.toByteArray());
  }

  public static byte[] newMaxFragmentLengthExtension(int lengthCode) {
    return newHelloExtension(1, new byte[] {(byte) lengthCode});
  }

  public static byte[] newServerNameExtension(final String hostName) {

    byte[] name = hostName.getBytes(ServerName.CHARSET);
    DatagramWriter writer = new DatagramWriter();
    writer.write(name.length + 3, 16); // server_name_list_length
    writer.writeByte((byte) 0x00);
    writer.write(name.length, 16);
    writer.writeBytes(name);
    return newHelloExtension(0, writer.toByteArray());
  }

  public static byte[] newHelloExtension(int typeCode, byte[] extensionBytes) {
    DatagramWriter writer = new DatagramWriter();
    writer.write(typeCode, 16);
    writer.write(extensionBytes.length, 16);
    writer.writeBytes(extensionBytes);
    return writer.toByteArray();
  }

  public static <T extends HandshakeMessage> T fromByteArray(
      byte[] byteArray, HandshakeParameter parameter) throws HandshakeException {
    HandshakeMessage hmsg = HandshakeMessage.fromByteArray(byteArray);
    return fromHandshakeMessage(hmsg, parameter);
  }

  @SuppressWarnings("unchecked")
  public static <T extends HandshakeMessage> T fromHandshakeMessage(
      HandshakeMessage message, HandshakeParameter parameter) throws HandshakeException {
    if (message instanceof GenericHandshakeMessage) {
      return (T)
          HandshakeMessage.fromGenericHandshakeMessage(
              (GenericHandshakeMessage) message, parameter);
    } else {
      return (T) message;
    }
  }

  /**
   * Parses a sequence of <em>DTLSCiphertext</em> structures into {@code Record} instances.
   *
   * <p>The binary representation is expected to comply with the <em>DTLSCiphertext</em> structure
   * defined in <a href="https://tools.ietf.org/html/rfc6347#section-4.3.1" target="_blank">RFC6347,
   * Section 4.3.1</a>.
   *
   * @param byteArray the raw binary representation containing one or more DTLSCiphertext structures
   * @param cidGenerator the connection id generator. May be {@code null}.
   * @param receiveNanos uptime nanoseconds of receiving this record
   * @return the {@code Record} instances
   * @throws NullPointerException if either one of the byte array or peer address is {@code null}
   */
  public static List<Record> fromByteArray(
      byte[] byteArray, ConnectionIdGenerator cidGenerator, long receiveNanos) {
    if (byteArray == null) {
      throw new NullPointerException("Byte array must not be null");
    }

    DatagramReader reader = new DatagramReader(byteArray, false);
    return Record.fromReader(reader, cidGenerator, receiveNanos);
  }
}
