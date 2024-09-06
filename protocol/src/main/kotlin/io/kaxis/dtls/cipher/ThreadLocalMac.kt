/*
 * COPYRIGHT Cplier 2024
 *
 * The copyright to the computer program(s) herein is the property of
 * Cplier Inc. The programs may be used and/or copied only with written
 * permission from Cplier Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 */

package io.kaxis.dtls.cipher

import javax.crypto.Mac

/**
 * Thread local mac. Uses [ThreadLocal] to cache calls to [Mac.getInstance]
 */
class ThreadLocalMac(algorithm: String) : ThreadLocalCrypto<Mac>({ Mac.getInstance(algorithm) })
