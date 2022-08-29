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
#include "threshold-v1.hpp"
using namespace bls;
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
    %template(PrivateKeyVector) vector<bls::PrivateKey>;
    %template(G1ElementVector) vector<bls::G1Element>;
    %template(G2ElementVector) vector<bls::G2Element>;
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
  %rename ("$ignore", fullname=1) CoreMPL::Aggregate(const vector<Bytes>& signatures);
  %rename ("$ignore", fullname=1) CoreMPL::AggregateVerify(const vector<Bytes>& pubkeys, const vector<Bytes>& messages, const Bytes& signature) override;
  %rename ("$ignore", fullname=1) CoreMPL::AggregateVerify(const vector<G1Element>& pubkeys, const vector<Bytes>& messages, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) AugSchemeMPL::Verify(const G1Element& pubkey, const Bytes& message, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) AugSchemeMPL::AggregateVerify(const vector<Bytes>& pubkeys, const vector<Bytes>& messages, const Bytes& signature) override;
  %rename ("$ignore", fullname=1) AugSchemeMPL::AggregateVerify(const vector<G1Element>& pubkeys, const vector<Bytes>& messages, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) BasicSchemeMPL::Verify(const G1Element& pubkey, const Bytes& message, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) BasicSchemeMPL::AggregateVerify(const vector<Bytes>& pubkeys, const vector<Bytes>& messages, const Bytes& signature) override;
  %rename ("$ignore", fullname=1) BasicSchemeMPL::AggregateVerify(const vector<G1Element>& pubkeys, const vector<Bytes>& messages, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) LegacySchemeMPL::Verify(const G1Element& pubkey, const Bytes& message, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) LegacySchemeMPL::AggregateVerify(const vector<Bytes>& pubkeys, const vector<Bytes>& messages, const Bytes& signature) override;
  %rename ("$ignore", fullname=1) LegacySchemeMPL::AggregateVerify(const vector<G1Element>& pubkeys, const vector<Bytes>& messages, const G2Element& signature) override;
  %rename ("$ignore", fullname=1) PopSchemeMPL::FastAggregateVerify(const vector<Bytes>& pubkeys, const Bytes& message, const Bytes& signature);

  %ignore Threshold::PrivateKeyRecover(const std::vector<PrivateKey>& sks, const std::vector<Bytes>& ids);
  %ignore Threshold::PublicKeyRecover(const std::vector<G1Element>& sks, const std::vector<Bytes>& ids);
  %ignore Threshold::SignatureRecover(const std::vector<G2Element>& sigs, const std::vector<Bytes>& ids);

  %extend BLS {
    static const long RLC_OK = 0;
    static long getContextError() {
        return core_get()->code;
    }
    static void setContextError(long error) {
        core_get()->code = error;
    }
    static long getContext() {
        return (long)core_get();
    }
  }
  %nspace Threshold;
}

// equality operators
%rename (objectEquals) operator==(ChainCode const &a, ChainCode const &b);
%rename (objectEquals) operator==(ExtendedPrivateKey const &a, ExtendedPrivateKey const &b);
%rename (objectEquals) operator==(ExtendedPublicKey const &a, ExtendedPublicKey const &b);
%rename (objectEquals) operator==(PrivateKey const &a, PrivateKey const &b);
%rename (objectEquals) operator==(PublicKey const &a, PublicKey const &b);
%rename (objectEquals) operator==(G1Element const &a, G1Element const &b);
%rename (objectEquals) operator==(G2Element const &a, G2Element const &b);
%rename (objectEquals) operator==(GTElement const &a, GTElement const &b);

// addition operators
%rename (add) operator+(const G1Element& a, const G1Element& b);
%rename (add) operator+(const G2Element& a, const G2Element& b);

// multiply operators
%rename (multiply) operator*(const G1Element& a, const G1Element& b);
%rename (multiply) operator*(const G2Element& a, const G2Element& b);
%rename (multiply) operator*(const G1Element& a, const PrivateKey& b);
%rename (multiply) operator*(const PrivateKey& a, const G1Element& b);
%rename (multiply) operator*(const G2Element& a, const PrivateKey& b);
%rename (multiply) operator*(const PrivateKey& a, const G2Element& b);
%rename (multiply) operator*(GTElement &a, GTElement &b);

// bitwise operators
%rename (andOperator) operator&(const G1Element &a, const G2Element &b);

// ignore these operators
%ignore operator<<;
%ignore operator=;
%ignore operator!=;
%ignore operator*=;
%ignore operator+=;
%ignore operator*(const G1Element &a, const bn_t &k);
%ignore operator*(const bn_t &k, const G1Element &a);
%ignore operator*(const G2Element &a, const bn_t &k);
%ignore operator*(const bn_t &k, const G2Element &a);
%ignore operator*(const PrivateKey& a, const bn_t& k);
%ignore operator*(const bn_t& k, const PrivateKey& a);

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

// Language independent exception handler
%include exception.i

%exception {
	try {
		$function
	} catch(std::string x) {
	    SWIG_exception(SWIG_ValueError, x.c_str());
	} catch(std::runtime_error x) {
        SWIG_exception(SWIG_RuntimeError, x.what());
    } catch(std::invalid_argument x) {
        SWIG_exception(SWIG_ValueError, x.what());
    } catch(std::length_error x) {
        SWIG_exception(SWIG_ValueError, x.what());
    } catch(std::logic_error x) {
        SWIG_exception(SWIG_ValueError, x.what());
    } catch(std::exception x) {
        SWIG_exception(SWIG_SystemError, x.what());
    } catch(...) {
		SWIG_exception(SWIG_RuntimeError,"Unknown exception");
	}
}

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
%include "src/main/cpp/threshold-v1.hpp"


