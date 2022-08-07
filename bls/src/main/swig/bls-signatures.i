%module DASHJBLS
%{
#include "bls-signatures/src/bls.hpp"
#include "bls-signatures/src/chaincode.hpp"
#include "bls-signatures/src/elements.hpp"
#include "bls-signatures/src/extendedprivatekey.hpp"
#include "bls-signatures/src/extendedpublickey.hpp"
#include "bls-signatures/src/hdkeys.hpp"
#include "bls-signatures/src/hkdf.hpp"
#include "bls-signatures/src/privatekey.hpp"
#include "bls-signatures/src/schemes.hpp"
#include "bls-signatures/src/threshold.hpp"
#include "bls-signatures/src/util.hpp"

%}

%include "std_vector.i"
%include "std_string.i"
%include "bytes.i"
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef long size_t;
namespace std {
  %template(Uint8Vector) vector<uint8_t>;
  %template(Uint8VectorVector) vector<vector<uint8_t>>;
}

namespace bls {
  %ignore BLS::SetSecureAllocator;
  %ignore G1Element::FromNative;
  %ignore G1Element::ToNative;
  %ignore G2Element::FromNative;
  %ignore G2Element::ToNative;
  %ignore GTElement::FromNative;
  %ignore GTElement::ToNative;
  %ignore Util;

  %rename("%(lowercamelcase)s", %$isfunction) "";
  %rename ("$ignore", fullname=1) AugSchemeMPL::Verify(const G1Element& pubkey, const Bytes& message, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) AugSchemeMPL::AggregateVerify(const vector<Bytes>& pubkeys, const vector<Bytes>& messages, const Bytes& signature) override;
  %rename ("$ignore", fullname=1) AugSchemeMPL::AggregateVerify(const vector<G1Element>& pubkeys, const vector<Bytes>& messages, const G2Element& signature) override;
}


//%ignore bls::Bytes::operator[](const int nIndex) const;
%rename (objectEquals) operator==(ChainCode const &a, ChainCode const &b);
%rename (objectEquals) operator==(ExtendedPrivateKey const &a, ExtendedPrivateKey const &b);
%rename (objectEquals) operator==(ExtendedPublicKey const &a, ExtendedPublicKey const &b);
%rename (objectEquals) operator==(PrivateKey const &a, PrivateKey const &b);
%rename (objectEquals) operator==(PublicKey const &a, PublicKey const &b);
%rename (objectEquals) operator==(G1Element const &a, G1Element const &b);
%rename (objectEquals) operator==(G2Element const &a, G2Element const &b);
//%rename (notEqualsChainCode) operator!=(ChainCode const &a, ChainCode const &b);
%ignore operator<<;

%typemap(jni) (unsigned char *) "jbyteArray"
%typemap(jtype) (unsigned char *) "byte[]"
%typemap(jstype) (unsigned char *) "byte[]"
%typemap(in) (unsigned char *) {
  $1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
}

%typemap(argout) (unsigned char *) {
  JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *) $1, 0);
}

%typemap(javain) (unsigned char *) "$javainput"

%typemap(freearg) (unsigned char *) ""

%include "src/main/cpp/bls-signatures/src/bls.hpp"
%include "src/main/cpp/bls-signatures/src/chaincode.hpp"
%include "src/main/cpp/bls-signatures/src/elements.hpp"
%include "src/main/cpp/bls-signatures/src/privatekey.hpp"
%include "src/main/cpp/bls-signatures/src/extendedpublickey.hpp"
%include "src/main/cpp/bls-signatures/src/extendedprivatekey.hpp"
%include "src/main/cpp/bls-signatures/src/hdkeys.hpp"
%include "src/main/cpp/bls-signatures/src/hkdf.hpp"
%include "src/main/cpp/bls-signatures/src/schemes.hpp"
%include "src/main/cpp/bls-signatures/src/threshold.hpp"

namespace std {
  %template(PrivateKeyVector) vector<bls::PrivateKey>;
  %template(G1ElementVector) vector<bls::G1Element>;
  %template(G2ElementVector) vector<bls::G2Element>;
}

