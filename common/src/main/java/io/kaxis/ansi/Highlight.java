/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.ansi;

/**
 * The Colorful highlight tool for all test cases. Ref <a
 * href="https://en.wikipedia.org/wiki/ANSI_escape_code#Colors">ANSI escape code</a>
 *
 * <pre>{@code
 * import io.kaxis.ansi.Highlight.*
 * public class ColorDemo {
 *   public static void main(String[] args) {
 *     System.out.println(GREEN_BACKGROUND + "Hello 2023!" + RESET);
 *   }
 * }
 * }</pre>
 *
 * Embedding ANSI color codes in text output will control the text foreground and background colors.
 *
 * <table style="width: 600pt">
 *   <tr><th style="padding:4px 15px;text-decoration:underline">Foreground</th><th style="width:50%"></th><th style="padding:4px 15px;text-decoration:underline">Background</th></tr>
 *   <tr><td style="padding:4px 15px">BLACK  </td><td style="background-color:#000"></td><td style="padding:4px 15px">BLACK_B  </td></tr>
 *   <tr><td style="padding:4px 15px">RED    </td><td style="background-color:#f00"></td><td style="padding:4px 15px">RED_B    </td></tr>
 *   <tr><td style="padding:4px 15px">GREEN  </td><td style="background-color:#0f0"></td><td style="padding:4px 15px">GREEN_B  </td></tr>
 *   <tr><td style="padding:4px 15px">YELLOW </td><td style="background-color:#ff0"></td><td style="padding:4px 15px">YELLOW_B </td></tr>
 *   <tr><td style="padding:4px 15px">BLUE   </td><td style="background-color:#00f"></td><td style="padding:4px 15px">BLUE_B   </td></tr>
 *   <tr><td style="padding:4px 15px">MAGENTA</td><td style="background-color:#f0f"></td><td style="padding:4px 15px">MAGENTA_B</td></tr>
 *   <tr><td style="padding:4px 15px">CYAN   </td><td style="background-color:#0ff"></td><td style="padding:4px 15px">CYAN_B   </td></tr>
 *   <tr><td style="padding:4px 15px">WHITE  </td><td style="background-color:#fff"></td><td style="padding:4px 15px">WHITE_B  </td></tr>
 * </table>
 *
 * @author galudisu
 */
public enum Highlight {

  // Color end string, color reset
  RESET("\033[0m"),

  // Regular Colors. Normal color, no bold, background color etc.
  BLACK("\033[0;30m"), // BLACK
  RED("\033[0;31m"), // RED
  GREEN("\033[0;32m"), // GREEN
  YELLOW("\033[0;33m"), // YELLOW
  BLUE("\033[0;34m"), // BLUE
  MAGENTA("\033[0;35m"), // MAGENTA
  CYAN("\033[0;36m"), // CYAN
  WHITE("\033[0;37m"), // WHITE

  // Bold
  BLACK_BOLD("\033[1;30m"), // BLACK
  RED_BOLD("\033[1;31m"), // RED
  GREEN_BOLD("\033[1;32m"), // GREEN
  YELLOW_BOLD("\033[1;33m"), // YELLOW
  BLUE_BOLD("\033[1;34m"), // BLUE
  MAGENTA_BOLD("\033[1;35m"), // MAGENTA
  CYAN_BOLD("\033[1;36m"), // CYAN
  WHITE_BOLD("\033[1;37m"), // WHITE

  // Underline
  BLACK_UNDERLINED("\033[4;30m"), // BLACK
  RED_UNDERLINED("\033[4;31m"), // RED
  GREEN_UNDERLINED("\033[4;32m"), // GREEN
  YELLOW_UNDERLINED("\033[4;33m"), // YELLOW
  BLUE_UNDERLINED("\033[4;34m"), // BLUE
  MAGENTA_UNDERLINED("\033[4;35m"), // MAGENTA
  CYAN_UNDERLINED("\033[4;36m"), // CYAN
  WHITE_UNDERLINED("\033[4;37m"), // WHITE

  // Background
  BLACK_BACKGROUND("\033[40m"), // BLACK
  RED_BACKGROUND("\033[41m"), // RED
  GREEN_BACKGROUND("\033[42m"), // GREEN
  YELLOW_BACKGROUND("\033[43m"), // YELLOW
  BLUE_BACKGROUND("\033[44m"), // BLUE
  MAGENTA_BACKGROUND("\033[45m"), // MAGENTA
  CYAN_BACKGROUND("\033[46m"), // CYAN
  WHITE_BACKGROUND("\033[47m"), // WHITE

  // High Intensity
  BLACK_BRIGHT("\033[0;90m"), // BLACK
  RED_BRIGHT("\033[0;91m"), // RED
  GREEN_BRIGHT("\033[0;92m"), // GREEN
  YELLOW_BRIGHT("\033[0;93m"), // YELLOW
  BLUE_BRIGHT("\033[0;94m"), // BLUE
  MAGENTA_BRIGHT("\033[0;95m"), // MAGENTA
  CYAN_BRIGHT("\033[0;96m"), // CYAN
  WHITE_BRIGHT("\033[0;97m"), // WHITE

  // Bold High Intensity
  BLACK_BOLD_BRIGHT("\033[1;90m"), // BLACK
  RED_BOLD_BRIGHT("\033[1;91m"), // RED
  GREEN_BOLD_BRIGHT("\033[1;92m"), // GREEN
  YELLOW_BOLD_BRIGHT("\033[1;93m"), // YELLOW
  BLUE_BOLD_BRIGHT("\033[1;94m"), // BLUE
  MAGENTA_BOLD_BRIGHT("\033[1;95m"), // MAGENTA
  CYAN_BOLD_BRIGHT("\033[1;96m"), // CYAN
  WHITE_BOLD_BRIGHT("\033[1;97m"), // WHITE

  // Intensity High backgrounds
  BLACK_BACKGROUND_BRIGHT("\033[0;100m"), // BLACK
  RED_BACKGROUND_BRIGHT("\033[0;101m"), // RED
  GREEN_BACKGROUND_BRIGHT("\033[0;102m"), // GREEN
  YELLOW_BACKGROUND_BRIGHT("\033[0;103m"), // YELLOW
  BLUE_BACKGROUND_BRIGHT("\033[0;104m"), // BLUE
  MAGENTA_BACKGROUND_BRIGHT("\033[0;105m"), // MAGENTA
  CYAN_BACKGROUND_BRIGHT("\033[0;106m"), // CYAN
  WHITE_BACKGROUND_BRIGHT("\033[0;107m"); // WHITE

  private final String code;

  Highlight(String code) {

    this.code = code;
  }

  @Override
  public String toString() {
    return code;
  }
}
