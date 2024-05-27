/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
 */

package io.kaxis.extension

import org.bouncycastle.operator.OperatorCreationException
import java.io.IOException
import java.security.GeneralSecurityException

fun interface KaxisBcJcaGenerator {
  @Throws(GeneralSecurityException::class, IOException::class, OperatorCreationException::class)
  fun spawn(algParameter: AlgParameter): AbstractMiscPemGroove
}
