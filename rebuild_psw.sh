#!/usr/bin/env bash
#cd psw 
#make clean
#cd ae/le
# make clean
# cd ../../../
# make psw DEBUG=1
make psw 
cd psw/ae/le
make
cd ../../../
# make deb_psw_pkg DEBUG=1
make deb_psw_pkg
make deb_local_repo
sudo apt-get remove libsgx-launch libsgx-urts libsgx-epid libsgx-quote-ex libsgx-dcap-ql libsgx-enclave-common libsgx-uae-service
sudo apt-get update
sudo apt-get install libsgx-launch libsgx-urts libsgx-enclave-common libsgx-uae-service
sudo apt-get install libsgx-epid 
sudo apt-get install libsgx-quote-ex 
sudo apt-get install libsgx-dcap-ql
