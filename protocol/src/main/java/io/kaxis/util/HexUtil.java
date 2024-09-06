/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.util;

public final class HexUtil {

  private HexUtil() {}

  private static final String NEWLINE = System.lineSeparator();

  private static final char[] BYTE2CHAR = new char[256];
  private static final char[] HEXDUMP_TABLE = new char[256 * 4];
  private static final String[] HEXPADDING = new String[16];
  private static final String[] HEXDUMP_ROWPREFIXES = new String[65536 >>> 4];
  private static final String[] BYTE2HEX = new String[256];
  private static final String[] BYTEPADDING = new String[16];
  private static final String[] BYTE2HEX_PAD = new String[256];
  private static final char[] DIGITS = "0123456789abcdef".toCharArray();

  static {
    // Generate the lookup table that converts a byte into a 2-digit hexadecimal integer.
    for (int i = 0; i < BYTE2HEX_PAD.length; i++) {
      String str = Integer.toHexString(i);
      BYTE2HEX_PAD[i] = i > 0xf ? str : ('0' + str);
    }
    for (int i = 0; i < 256; i++) {
      HEXDUMP_TABLE[i << 1] = DIGITS[i >>> 4 & 0x0F];
      HEXDUMP_TABLE[(i << 1) + 1] = DIGITS[i & 0x0F];
    }

    int i;

    // Generate the lookup table for hex dump paddings
    for (i = 0; i < HEXPADDING.length; i++) {
      int padding = HEXPADDING.length - i;
      HEXPADDING[i] = "   ".repeat(Math.max(0, padding));
    }

    // Generate the lookup table for the start-offset header in each row (up to 64KiB).
    for (i = 0; i < HEXDUMP_ROWPREFIXES.length; i++) {
      StringBuilder buf = new StringBuilder(12);
      buf.append(NEWLINE);
      buf.append(Long.toHexString(((long) i << 4) & 0xFFFFFFFFL | 0x100000000L));
      buf.setCharAt(buf.length() - 9, '│');
      buf.append('│');
      HEXDUMP_ROWPREFIXES[i] = buf.toString();
    }

    // Generate the lookup table for byte-to-hex-dump conversion
    for (i = 0; i < BYTE2HEX.length; i++) {
      BYTE2HEX[i] = ' ' + byteToHexStringPadded(i);
    }

    // Generate the lookup table for byte dump paddings
    for (i = 0; i < BYTEPADDING.length; i++) {
      int padding = BYTEPADDING.length - i;
      BYTEPADDING[i] = " ".repeat(Math.max(0, padding));
    }

    // Generate the lookup table for byte-to-char conversion
    for (i = 0; i < BYTE2CHAR.length; i++) {
      if (i <= 0x1f || i >= 0x7f) {
        BYTE2CHAR[i] = '.';
      } else {
        BYTE2CHAR[i] = (char) i;
      }
    }
  }

  private static String byteToHexStringPadded(int value) {
    return BYTE2HEX_PAD[value & 0xff];
  }

  public static String hexDump(byte[] array, int fromIndex, int length) {
    if (length < 0) {
      throw new IllegalArgumentException("Length must be a positive integer");
    }
    if (length == 0) {
      return "";
    }

    int endIndex = fromIndex + length;
    char[] buf = new char[length << 1];

    int srcIdx = fromIndex;
    int dstIdx = 0;
    for (; srcIdx < endIndex; srcIdx++, dstIdx += 2) {
      System.arraycopy(HEXDUMP_TABLE, (array[srcIdx] & 0xFF) << 1, buf, dstIdx, 2);
    }

    return new String(buf);
  }

  public static String prettyHexDump(byte[] buffer, int offset, int length) {
    if (length == 0) {
      return "";
    } else {
      int rows = length / 16 + ((length & 15) == 0 ? 0 : 1) + 4;
      StringBuilder buf = new StringBuilder(rows * 80);
      appendPrettyHexDump(buf, buffer, offset, length);
      return buf.toString();
    }
  }

  private static void appendPrettyHexDump(StringBuilder dump, byte[] buf, int offset, int length) {
    if (length == 0) {
      return;
    }
    dump.append(NEWLINE);
    dump.append("         ┌─────────────────────────────────────────────────┐");
    dump.append(NEWLINE);
    dump.append("         │  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f │");
    dump.append(NEWLINE);
    dump.append("┌────────┼─────────────────────────────────────────────────┼────────────────┐");

    final int fullRows = length >>> 4;
    final int remainder = length & 0xF;

    // Dump the rows which have 16 bytes.
    for (int row = 0; row < fullRows; row++) {
      int rowStartIndex = (row << 4) + offset;

      // Per-row prefix.
      appendHexDumpRowPrefix(dump, row, rowStartIndex);

      // Hex dump
      int rowEndIndex = rowStartIndex + 16;
      for (int j = rowStartIndex; j < rowEndIndex; j++) {
        dump.append(BYTE2HEX[buf[j] & 0xFF]);
      }
      dump.append(" │");

      // ASCII dump
      for (int j = rowStartIndex; j < rowEndIndex; j++) {
        dump.append(BYTE2CHAR[buf[j] & 0xFF]);
      }
      dump.append('│');
    }

    // Dump the last row which has less than 16 bytes.
    if (remainder != 0) {
      int rowStartIndex = (fullRows << 4) + offset;
      appendHexDumpRowPrefix(dump, fullRows, rowStartIndex);

      // Hex dump
      int rowEndIndex = rowStartIndex + remainder;
      for (int j = rowStartIndex; j < rowEndIndex; j++) {
        dump.append(BYTE2HEX[buf[j] & 0xFF]);
      }
      dump.append(HEXPADDING[remainder]);
      dump.append(" │");

      // Ascii dump
      for (int j = rowStartIndex; j < rowEndIndex; j++) {
        dump.append(BYTE2CHAR[buf[j] & 0xFF]);
      }
      dump.append(BYTEPADDING[remainder]);
      dump.append('│');
    }

    dump.append(NEWLINE);
    dump.append("└────────┴─────────────────────────────────────────────────┴────────────────┘");
    dump.append(NEWLINE);
  }

  private static void appendHexDumpRowPrefix(StringBuilder dump, int row, int rowStartIndex) {
    if (row < HEXDUMP_ROWPREFIXES.length) {
      dump.append(HEXDUMP_ROWPREFIXES[row]);
    } else {
      dump.append(NEWLINE);
      dump.append(Long.toHexString(rowStartIndex & 0xFFFFFFFFL | 0x100000000L));
      dump.setCharAt(dump.length() - 9, '│');
      dump.append('│');
    }
  }
}
