/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package org.zipj.bls;

public class G1Element {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected G1Element(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(G1Element obj) {
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
        ZIPJBLSJNI.delete_G1Element(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public G1Element() {
    this(ZIPJBLSJNI.new_G1Element__SWIG_0(), true);
  }

  public static G1Element fromBytes(byte[] bytes, boolean fLegacy) {
    return new G1Element(ZIPJBLSJNI.G1Element_fromBytes__SWIG_0(bytes, fLegacy), true);
  }

  public static G1Element fromBytes(byte[] bytes) {
    return new G1Element(ZIPJBLSJNI.G1Element_fromBytes__SWIG_1(bytes), true);
  }

  public static G1Element fromBytesUnchecked(byte[] bytes, boolean fLegacy) {
    return new G1Element(ZIPJBLSJNI.G1Element_fromBytesUnchecked__SWIG_0(bytes, fLegacy), true);
  }

  public static G1Element fromBytesUnchecked(byte[] bytes) {
    return new G1Element(ZIPJBLSJNI.G1Element_fromBytesUnchecked__SWIG_1(bytes), true);
  }

  public static G1Element fromMessage(byte[] message, byte[] dst, int dst_len) {
    return new G1Element(ZIPJBLSJNI.G1Element_fromMessage(message, dst, dst_len), true);
  }

  public static G1Element generator() {
    return new G1Element(ZIPJBLSJNI.G1Element_generator(), true);
  }

  public boolean isValid() {
    return ZIPJBLSJNI.G1Element_isValid(swigCPtr, this);
  }

  public void checkValid() {
    ZIPJBLSJNI.G1Element_checkValid(swigCPtr, this);
  }

  public G1Element negate() {
    return new G1Element(ZIPJBLSJNI.G1Element_negate(swigCPtr, this), true);
  }

  public GTElement pair(G2Element b) {
    return new GTElement(ZIPJBLSJNI.G1Element_pair(swigCPtr, this, G2Element.getCPtr(b), b), true);
  }

  public long getFingerprint(boolean fLegacy) {
    return ZIPJBLSJNI.G1Element_getFingerprint__SWIG_0(swigCPtr, this, fLegacy);
  }

  public long getFingerprint() {
    return ZIPJBLSJNI.G1Element_getFingerprint__SWIG_1(swigCPtr, this);
  }

  public byte[] serialize(boolean fLegacy) { return ZIPJBLSJNI.G1Element_serialize__SWIG_0(swigCPtr, this, fLegacy); }

  public byte[] serialize() { return ZIPJBLSJNI.G1Element_serialize__SWIG_1(swigCPtr, this); }

  public G1Element(G1Element other) {
    this(ZIPJBLSJNI.new_G1Element__SWIG_1(G1Element.getCPtr(other), other), true);
  }

  public final static int SIZE = ZIPJBLSJNI.G1Element_SIZE_get();
}
