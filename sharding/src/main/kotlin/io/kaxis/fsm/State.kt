/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.fsm

import io.kaxis.Configuration
import io.kaxis.ansi.Highlight
import io.kaxis.dtls.*
import io.kaxis.dtls.message.AlertMessage
import io.kaxis.dtls.message.ChangeCipherSpecMessage
import io.kaxis.dtls.message.handshake.*
import io.kaxis.util.Utility
import java.net.InetSocketAddress

/**
 * Record Layer state for **SERVER**.
 *
 * A Mealy machine is a 6-tuple(`S`, `S₀`, `Σ`, `Λ`, `T`, `G`) where:
 *
 * - `S`: Finite set of states.
 * - `S₀`: Start state, where `S₀ ∈ S`.
 * - `Σ`: Finite set of input alphabet.
 * - `Λ`: Finite set of output alphabet.
 * - `T`: State transition function: `T: S x Σ -> S`.
 * - `G`: Output function `G: S x Σ -> Λ`.
 */
open class State(
  var stage: Stage = Stage.S0,
) : FSMSerializable, Configuration {
  companion object {
    @JvmStatic
    fun empty(): State = State()
  }

  var resumptionRequired: Boolean = false

  // Use peer-address for handshake.
  var peerAddress: InetSocketAddress? = null

  // Once handshake established, use cid for data transform.
  // And peerAddress will set to null
  var cid: ConnectionId? = null

  var dtlsContext: DTLSContext? = null

  // mark the field like this to ignore it during de/serialization
  // for security issue, SecureRandom will not be persisted.
  @delegate:Transient
  val idGenerator: ConnectionIdGenerator by lazy { DefaultConnectionIdGenerator(cidLength) }

  @delegate:Transient
  val cookieGenerator: CookieGenerator by lazy { CookieGenerator() }

  // /////////////////////////////////////////////////////////////////////////////////

  infix fun goto(stage: Stage): State {
    this.stage = stage
    return this
  }

  override fun toString(): String {
    return StringBuilder().apply sb@{
      this@sb.append(Utility.LINE_SEPARATOR)
      val indentation = Utility.indentation(2)
      this@sb.append("STATE: ").append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation)
        .append("stage: ")
        .append(Highlight.CYAN_BOLD_BRIGHT)
        .append(stage).append(Highlight.RESET).append(Utility.LINE_SEPARATOR)
      this@sb.append(indentation)
        .append("resumption: ")
        .append(Highlight.RED_BOLD_BRIGHT)
        .append(resumptionRequired).append(Highlight.RESET)
        .append(Utility.LINE_SEPARATOR)
      if (peerAddress != null) {
        this@sb.append(indentation)
          .append("peerAddress: ")
          .append(Highlight.BLUE_BOLD_BRIGHT)
          .append(peerAddress).append(Highlight.RESET).append(Utility.LINE_SEPARATOR)
      }
      if (cid != null) {
        this@sb.append(indentation)
          .append("cid: ")
          .append(Highlight.GREEN_BOLD_BRIGHT)
          .append(cid.toString()).append(Highlight.RESET).append(Utility.LINE_SEPARATOR)
      }
      if (dtlsContext != null) {
        this@sb.append(indentation)
          .append("dtlsContext: ")
          .append(Highlight.MAGENTA_BOLD_BRIGHT)
          .append(dtlsContext.toString()).append(Highlight.RESET).append(dtlsContext).append(Utility.LINE_SEPARATOR)
      }
    }.toString()
  }

  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    result = prime * result + stage.hashCode()
    result = prime * result + (if (resumptionRequired) 1 else 0)
    result = prime * result + peerAddress.hashCode()
    result = prime * result + cid.hashCode()
    result = prime * result + dtlsContext.hashCode()
    return result
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) {
      return true
    } else if (other == null) {
      return false
    } else if (other !is State) {
      return false
    }
    if (stage != other.stage) {
      return false
    }
    if (resumptionRequired != other.resumptionRequired) {
      return false
    }
    if (peerAddress != other.peerAddress) {
      return false
    }
    if (cid != other.cid) {
      return false
    }
    if (dtlsContext != other.dtlsContext) {
      return false
    }
    return true
  }

  enum class Stage(val stage: Int) {
    /**
     * This is the beginning state of the implementation.
     */
    S0(0),

    /**
     * Sending the first [ClientHello] results in the state transition `S₀ -> S₁`.
     * The server responded with a [HelloVerifyRequest].
     */
    S1(1),

    /**
     * Sending the final [Finished] message, results in a [AlertMessage.AlertDescription.DECODE_ERROR]. The server
     * was not able to decrypt the encrypted finished message. And send a [AlertMessage.AlertLevel.FATAL]. The
     * handshake has failed.
     */
    S2(2),

    /**
     * Sending the second [ClientHello] results in the state transition `S₀ -> S₁ -> S₃`. The server responded with
     * the three [ServerHello]. [CertificateMessage], [ServerHelloDone] messages. All normal behavior thus far.
     */
    S3(3),

    /**
     * Sending the [ClientKeyExchange] message results in the state `S₀ -> S₁ -> S₃ -> S₄`. The server
     * did not respond with a message, because it is waiting for the next messages to come.
     */
    S4(4),

    /**
     * Sending the [ChangeCipherSpecMessage] results in the state transition `S₀ -> S₁ -> S₃ -> S₄ -> S₅`.
     */
    S5(5), ;

    companion object {
      fun fromState(stage: Int): Stage {
        return when (stage) {
          0 -> S0
          1 -> S1
          2 -> S2
          3 -> S3
          4 -> S4
          5 -> S5
          else -> throw IllegalArgumentException("fail to deserialize stage: $stage")
        }
      }
    }
  }

  // <editor-fold desc="MEALY FSM">
  @Deprecated("Marked as deprecated since pekko state machine already handle this.")
  enum class MealyFsm(val fsm: Int) {
    /**
     * The implementation performs whatever computation necessary to prepare the next flight of the messages
     * and put the messages in the buffer ready to be sent.
     */
    PREPARING(0),

    /**
     * The implementation transmits the buffered message; once the messages haven been sent, the implementation enters
     * in the [FINISHED] state (if the last message has been sent), or in the [WAITING] state.
     */
    SENDING(1),

    /**
     * In this [WAITING] state the implementation waits for the next flight to be received within a
     * certain amount of time. If nothing is received within a certain time, it resends the last buffered messages; the
     * same thing happens when a retransmission is received. If instead a regular flight is received, the next state is
     * the [PREPARING] state, in which the next flight is prepared, otherwise if the last message has been received,
     * the implementation transits to the [FINISHED] state.
     */
    WAITING(2),

    /**
     * The implementation receives the next flight; If it is the last flight, then the handshake is completed;
     * otherwise it returns to the [PREPARING] state (for instance in case of the server in the handshake, it
     * receives the client [FINISHED] message, but the server still needs to send the [ChangeCipherSpecMessage]
     * and [Finished].
     */
    FINISHED(3), ;

    companion object {
      fun fromMealyFsm(fsm: Int): MealyFsm {
        return when (fsm) {
          0 -> PREPARING
          1 -> SENDING
          2 -> WAITING
          3 -> FINISHED
          else -> throw IllegalArgumentException("fail to deserialize fsm: $fsm")
        }
      }
    }
  }
  // </editor-fold>
}
