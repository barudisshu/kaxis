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

import io.kaxis.CborSerializable

// https://doc.org.apache.pekko.io/docs/pekko/current/persistence-query.html
// https://doc.org.apache.pekko.io/docs/pekko/current/typed/fsm.html

/**
 * A Finite State Machine of DTLS server impl.
 *
 * @see <img src="https://user-images.githubusercontent.com/37236920/152256099-150df823-9884-45e4-9c0c-8c4dc5a833ad.png"/>
 */
interface FSMSerializable : CborSerializable
