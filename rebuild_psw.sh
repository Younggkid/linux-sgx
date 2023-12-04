#!/usr/bin/env bash
cd psw 
make clean
cd ae/le
make clean
cd ../../../
make psw DEBUG=1
cd psw/ae/le
make
cd ../../../
make deb_psw_pkg
make deb_local_repo

