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
make deb_psw_pkg DEBUG=1
make deb_local_repo
sudo apt-get remove libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex libsgx-dcap-ql
sudo apt-get update
sudo apt-get install libsgx-launch libsgx-urts
sudo apt-get install libsgx-epid 
sudo apt-get install libsgx-quote-ex 
sudo apt-get install libsgx-dcap-ql
