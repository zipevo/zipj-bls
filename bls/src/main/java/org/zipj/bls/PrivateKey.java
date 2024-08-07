/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package org.zipj.bls;

public class PrivateKey {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected PrivateKey(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(PrivateKey obj) {
    return (obj == null) ? 0 : obj.swigCPtr;
  }

  @SuppressWarnings("deprecation")
  protected void finalize() {
    delete();
  }

  public synchronized void delete() {
    if (swigCPtr != 0) {
      if (swigCMemOwn) {
        swigCMemOwn = false;
        ZIPJBLSJNI.delete_PrivateKey(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public static PrivateKey fromSeedBIP32(byte[] seed) {
    return new PrivateKey(ZIPJBLSJNI.PrivateKey_fromSeedBIP32(seed), true);
  }

  public static PrivateKey randomPrivateKey() {
    return new PrivateKey(ZIPJBLSJNI.PrivateKey_randomPrivateKey(), true);
  }

  public static PrivateKey fromBytes(byte[] bytes, boolean modOrder) {
    return new PrivateKey(ZIPJBLSJNI.PrivateKey_fromBytes__SWIG_0(bytes, modOrder), true);
  }

  public static PrivateKey fromBytes(byte[] bytes) {
    return new PrivateKey(ZIPJBLSJNI.PrivateKey_fromBytes__SWIG_1(bytes), true);
  }

  public static PrivateKey aggregate(PrivateKeyVector privateKeys) {
    return new PrivateKey(ZIPJBLSJNI.PrivateKey_aggregate(PrivateKeyVector.getCPtr(privateKeys), privateKeys), true);
  }

  public PrivateKey() {
    this(ZIPJBLSJNI.new_PrivateKey__SWIG_0(), true);
  }

  public PrivateKey(PrivateKey k) {
    this(ZIPJBLSJNI.new_PrivateKey__SWIG_1(PrivateKey.getCPtr(k), k), true);
  }

  public G1Element getG1Element() {
    return new G1Element(ZIPJBLSJNI.PrivateKey_getG1Element(swigCPtr, this), false);
  }

  public G2Element getG2Element() {
    return new G2Element(ZIPJBLSJNI.PrivateKey_getG2Element(swigCPtr, this), false);
  }

  public G2Element getG2Power(G2Element element) {
    return new G2Element(ZIPJBLSJNI.PrivateKey_getG2Power(swigCPtr, this, G2Element.getCPtr(element), element), true);
  }

  public boolean isZero() {
    return ZIPJBLSJNI.PrivateKey_isZero(swigCPtr, this);
  }

  public void serialize(byte[] buffer) {
    ZIPJBLSJNI.PrivateKey_serialize__SWIG_0(swigCPtr, this, buffer);
  }

  public byte[] serialize(boolean fLegacy) { return ZIPJBLSJNI.PrivateKey_serialize__SWIG_1(swigCPtr, this, fLegacy); }

  public byte[] serialize() { return ZIPJBLSJNI.PrivateKey_serialize__SWIG_2(swigCPtr, this); }

  public G2Element signG2(byte[] msg, long len, byte[] dst, long dst_len, boolean fLegacy) {
    return new G2Element(ZIPJBLSJNI.PrivateKey_signG2__SWIG_0(swigCPtr, this, msg, len, dst, dst_len, fLegacy), true);
  }

  public G2Element signG2(byte[] msg, long len, byte[] dst, long dst_len) {
    return new G2Element(ZIPJBLSJNI.PrivateKey_signG2__SWIG_1(swigCPtr, this, msg, len, dst, dst_len), true);
  }

  public boolean hasKeyData() {
    return ZIPJBLSJNI.PrivateKey_hasKeyData(swigCPtr, this);
  }

  public final static int PRIVATE_KEY_SIZE = ZIPJBLSJNI.PrivateKey_PRIVATE_KEY_SIZE_get();
}
