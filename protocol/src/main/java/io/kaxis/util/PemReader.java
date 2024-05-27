/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */
package io.kaxis.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PemReader {
  private static final Logger LOGGER = LoggerFactory.getLogger(PemReader.class);

  private static final Pattern BEGIN_PATTERN = Pattern.compile("^\\-+BEGIN\\s+([\\w\\s]+)\\-+$");

  private static final Pattern END_PATTERN = Pattern.compile("^\\-+END\\s+([\\w\\s]+)\\-+$");

  private final BufferedReader reader;
  private String tag;

  public PemReader(InputStream in) {
    reader = new BufferedReader(new InputStreamReader(in));
  }

  public void close() {
    try {
      reader.close();
    } catch (IOException e) {
    }
  }

  public String readNextBegin() throws IOException {
    String line;
    tag = null;
    while ((line = reader.readLine()) != null) {
      Matcher matcher = BEGIN_PATTERN.matcher(line);
      if (matcher.matches()) {
        tag = matcher.group(1);
        LOGGER.debug("Found Begin of {}", tag);
        break;
      }
    }
    return tag;
  }

  public byte[] readToEnd() throws IOException {
    String line;
    StringBuilder buffer = new StringBuilder();

    while ((line = reader.readLine()) != null) {
      Matcher matcher = END_PATTERN.matcher(line);
      if (matcher.matches()) {
        String end = matcher.group(1);
        if (end.equals(tag)) {
          byte[] decode = Base64.decode(buffer.toString());
          LOGGER.debug("Found End of {}", tag);
          return decode;
        } else {
          LOGGER.warn("Found End of {}, but expected {}!", end, tag);
          break;
        }
      }
      buffer.append(line);
    }
    tag = null;
    return null;
  }
}
