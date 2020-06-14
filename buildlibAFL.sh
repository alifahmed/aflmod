#!/bin/bash

clang++ -stdlib=libc++ -std=c++11 -O3 -c cgs_driver.cpp
clang -Wno-pointer-sign -c llvm_mode/afl-llvm-rt.o.c -O3 -I.
ar r libAFL.a cgs_driver.o afl-llvm-rt.o.o
