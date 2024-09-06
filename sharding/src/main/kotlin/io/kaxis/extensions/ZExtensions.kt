/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
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
