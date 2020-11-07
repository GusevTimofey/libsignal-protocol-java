/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.groups.ratchet;

import org.whispersystems.libsignal.my.own.HacGOSTR3411_2012_256;

/**
 * Each SenderKey is a "chain" of keys, each derived from the previous.
 *
 * At any given point in time, the state of a SenderKey can be represented
 * as the current chain key value, along with its iteration count.  From there,
 * subsequent iterations can be derived, as well as individual message keys from
 * each chain key.
 *
 * @author Moxie Marlinspike
 */
public class SenderChainKey {

  private static final byte[] MESSAGE_KEY_SEED = {0x01};
  private static final byte[] CHAIN_KEY_SEED   = {0x02};

  private final int    iteration;
  private final byte[] chainKey;

  public SenderChainKey(int iteration, byte[] chainKey) {
    this.iteration = iteration;
    this.chainKey  = chainKey;
  }

  public int getIteration() {
    return iteration;
  }

  public SenderMessageKey getSenderMessageKey() {
    return new SenderMessageKey(iteration, getDerivative(MESSAGE_KEY_SEED, chainKey));
  }

  public SenderChainKey getNext() {
    return new SenderChainKey(iteration + 1, getDerivative(CHAIN_KEY_SEED, chainKey));
  }

  public byte[] getSeed() {
    return chainKey;
  }

  private byte[] getDerivative(byte[] seed, byte[] key) {
    try {
      HacGOSTR3411_2012_256 mac = new HacGOSTR3411_2012_256();
      return mac.makeHmac(key, seed);
    } catch (Throwable e) {
      throw new AssertionError(e);
    }
  }

}
