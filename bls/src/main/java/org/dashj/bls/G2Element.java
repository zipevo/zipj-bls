/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 4.0.2
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

package org.dashj.bls;

public class G2Element {
  private transient long swigCPtr;
  protected transient boolean swigCMemOwn;

  protected G2Element(long cPtr, boolean cMemoryOwn) {
    swigCMemOwn = cMemoryOwn;
    swigCPtr = cPtr;
  }

  protected static long getCPtr(G2Element obj) {
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
        DASHJBLSJNI.delete_G2Element(swigCPtr);
      }
      swigCPtr = 0;
    }
  }

  public G2Element() {
    this(DASHJBLSJNI.new_G2Element__SWIG_0(), true);
  }

  public static G2Element fromBytes(byte[] bytes, boolean fLegacy) {
    return new G2Element(DASHJBLSJNI.G2Element_fromBytes__SWIG_0(bytes, fLegacy), true);
  }

  public static G2Element fromBytes(byte[] bytes) {
    return new G2Element(DASHJBLSJNI.G2Element_fromBytes__SWIG_1(bytes), true);
  }

  public static G2Element fromBytesUnchecked(byte[] bytes, boolean fLegacy) {
    return new G2Element(DASHJBLSJNI.G2Element_fromBytesUnchecked__SWIG_0(bytes, fLegacy), true);
  }

  public static G2Element fromBytesUnchecked(byte[] bytes) {
    return new G2Element(DASHJBLSJNI.G2Element_fromBytesUnchecked__SWIG_1(bytes), true);
  }

  public static G2Element fromMessage(byte[] message, byte[] dst, int dst_len, boolean fLegacy) {
    return new G2Element(DASHJBLSJNI.G2Element_fromMessage__SWIG_0(message, dst, dst_len, fLegacy), true);
  }

  public static G2Element fromMessage(byte[] message, byte[] dst, int dst_len) {
    return new G2Element(DASHJBLSJNI.G2Element_fromMessage__SWIG_1(message, dst, dst_len), true);
  }

  public static G2Element generator() {
    return new G2Element(DASHJBLSJNI.G2Element_generator(), true);
  }

  public boolean isValid() {
    return DASHJBLSJNI.G2Element_isValid(swigCPtr, this);
  }

  public void checkValid() {
    DASHJBLSJNI.G2Element_checkValid(swigCPtr, this);
  }

  public G2Element negate() {
    return new G2Element(DASHJBLSJNI.G2Element_negate(swigCPtr, this), true);
  }

  public GTElement pair(G1Element a) {
    return new GTElement(DASHJBLSJNI.G2Element_pair(swigCPtr, this, G1Element.getCPtr(a), a), true);
  }

  public byte[] serialize(boolean fLegacy) { return DASHJBLSJNI.G2Element_serialize__SWIG_0(swigCPtr, this, fLegacy); }

  public byte[] serialize() { return DASHJBLSJNI.G2Element_serialize__SWIG_1(swigCPtr, this); }

  public G2Element(G2Element other) {
    this(DASHJBLSJNI.new_G2Element__SWIG_1(G2Element.getCPtr(other), other), true);
  }

  public final static int SIZE = DASHJBLSJNI.G2Element_SIZE_get();
}