[![Linux and MacOS build status](https://ci.appveyor.com/api/projects/status/x790ve5msewmva2b/branch/master?svg=true)](https://ci.appveyor.com/project/litespeedtech/lsquic-linux/branch/master)
[![Windows build status](https://ci.appveyor.com/api/projects/status/ij4n3vy343pkgm1j/branch/master?svg=true)](https://ci.appveyor.com/project/litespeedtech/lsquic-windows/branch/master)
[![FreeBSD build status](https://api.cirrus-ci.com/github/litespeedtech/lsquic.svg)](https://cirrus-ci.com/github/litespeedtech/lsquic)
[![Documentation Status](https://readthedocs.org/projects/lsquic/badge/?version=latest)](https://lsquic.readthedocs.io/en/latest/?badge=latest)

CCAS README
=============================================

Description
-----------

This is a implemented project to study the Dynamic Switching Technology for Congestion Control Algorithms.  

This project is developed based on Lsquic (The commit ID of development is '0e536e04').

Currently supported Congestion Control Algorithms: Cubic, BBR, Copa.

Standard Compliance
-------------------

Requirements
------------

To build CCAS, you need CMake, zlib.  The example program
uses libevent to provide the event loop.

Building CCAS
------------------
```
cd lsquic
cmake -DBORINGSSL_DIR=$BORINGSSL .
make
```

Platforms
---------

The library has been tested on the following platforms:
- Linux
  - i386
  - x86_64
  - ARM (Raspberry Pi 3)
- FreeBSD
  - i386
- MacOS
  - x86_64
- iOS
  - ARM
- Android
  - ARM
- Windows
  - x86_64
