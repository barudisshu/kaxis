/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.extension

import org.bouncycastle.operator.OperatorCreationException
import java.io.IOException
import java.security.GeneralSecurityException

fun interface KaxisBcJcaGenerator {
  @Throws(GeneralSecurityException::class, IOException::class, OperatorCreationException::class)
  fun spawn(algParameter: AlgParameter): AbstractMiscPemGroove
}
