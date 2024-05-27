/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.DisplayName.class)
class Base64Test {

  public static List<byte[]> params() {
    return Arrays.asList(
        new byte[] {0x01, 0x02, 0x03},
        new byte[] {0x01, 0x02, 0x03, 0x04},
        new byte[] {0x01, 0x02, 0x03, 0x04, 0x05});
  }

  @ParameterizedTest(name = "0{index}: parameter: ''{0}''")
  @MethodSource("params")
  void testEncodeBytesRecognizesNoPaddingOption(byte[] input) throws IOException {
    String result = Base64.encodeBytes(input, Base64.ENCODE | Base64.URL_SAFE);
    int excessBytes = input.length % 3;
    int expectedLength = (1 + (excessBytes > 0 ? 1 : 0)) * 4;
    assertEquals(result.length(), expectedLength);
    if (input.length % 3 > 0) {
      assertTrue(result.endsWith("="));
    }
    result = Base64.encodeBytes(input, Base64.ENCODE | Base64.URL_SAFE | Base64.NO_PADDING);
    assertFalse(result.endsWith("="));
    expectedLength = 4 + (excessBytes > 0 ? excessBytes + 1 : 0);
    assertEquals(result.length(), expectedLength);
  }
}
