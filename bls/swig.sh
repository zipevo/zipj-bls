#! /bin/sh
#  -debug-symbols
rm -rf src/main/java/org/dashj/bls/v1
mkdir src/main/java/org/dashj/bls/v1
swig -v -c++ -java -package org.dashj.bls.v1 -outdir src/main/java/org/dashj/bls/v1 -o src/main/cpp/bls-signatures-v1.cpp src/main/swig/bls-signatures.i
sed -ie "s/ Bytes/ bls::Bytes/g" src/main/cpp/bls-signatures-v1.cpp
sed -ie "s/(Bytes/(bls::Bytes/g" src/main/cpp/bls-signatures-v1.cpp