#! /bin/sh
#  -debug-symbols
swig -v -c++ -java -package org.zipj.bls -outdir src/main/java/org/zipj/bls -o src/main/cpp/bls-signatures-v1.cpp src/main/swig/bls-signatures.i