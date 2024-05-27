/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.rule

import io.kaxis.util.ClockUtil
import org.junit.jupiter.api.extension.AfterEachCallback
import org.junit.jupiter.api.extension.BeforeEachCallback
import org.junit.jupiter.api.extension.ExtensionContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.util.concurrent.TimeUnit

class TestTimeExtension : BeforeEachCallback, AfterEachCallback {
  companion object {
    private val LOGGER: Logger = LoggerFactory.getLogger(TestTimeExtension::class.java)

    /**
     * Current test time shift in nanoseconds.
     */
    private var timeShiftNanos: Long = 0

    /**
     * Fix test time.
     */
    private var timeFixed: Long? = null

    @JvmStatic
    @Synchronized
    fun setFixedTestTime(enabled: Boolean) {
      LOGGER.debug("set fixed test time {}", enabled)
      timeFixed =
        if (enabled) {
          System.nanoTime()
        } else {
          null
        }
    }

    @JvmStatic
    @Synchronized
    fun addTestTimeShift(
      delta: Long,
      unit: TimeUnit,
    ) {
      LOGGER.debug("add {} {} to timeshift {} ms", delta, unit, timeShiftNanos)
      timeShiftNanos += unit.toNanos(delta)
    }

    @JvmStatic
    @Synchronized
    fun setTestTimeShift(
      shift: Long,
      unit: TimeUnit,
    ) {
      LOGGER.debug("set {} {} as timeshift", shift, unit)
      timeShiftNanos = unit.toNanos(shift)
    }

    @JvmStatic
    @Synchronized
    fun getTestTimeShiftNanos() = timeShiftNanos
  }

  private val handler =
    ClockUtil.Realtime {
      val shift: Long
      val fixed: Long?

      synchronized(this@TestTimeExtension) {
        shift = timeShiftNanos
        fixed = timeFixed
      }
      if (fixed != null) {
        fixed + shift
      } else {
        System.nanoTime() + shift
      }
    }

  override fun beforeEach(context: ExtensionContext?) {
    ClockUtil.setRealtimeHandler(handler)
  }

  override fun afterEach(context: ExtensionContext?) {
    if (getTestTimeShiftNanos() != 0L) {
      setTestTimeShift(0L, TimeUnit.NANOSECONDS)
    }
  }
}
