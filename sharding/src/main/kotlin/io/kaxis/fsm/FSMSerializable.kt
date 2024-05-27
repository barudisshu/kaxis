/*
 * Copyright (c) 2024. Galudisu@gmail.com
 *
 * All rights reserved.
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
