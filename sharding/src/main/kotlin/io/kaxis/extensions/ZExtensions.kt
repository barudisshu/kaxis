/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extensions

import io.kaxis.util.DatagramWriter
import io.kaxis.util.SerializationUtil
import java.net.InetSocketAddress

// TODO) query from journal using [ClusterCidManagement].
fun InetSocketAddress.toEntity(): String {
  val writer = DatagramWriter()
  SerializationUtil.write(writer, this)
  val data = writer.toByteArray()
  return String(data)
}
