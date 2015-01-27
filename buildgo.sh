#!/usr/bin/env bash
if [ "`uname -a | grep Linux`" != "" ]; then
	rm *.syso
	rm -rf build/* obj/*
	make -j all
#	cp build/libquic.a libquic_linux_amd64.syso
#	cp boringssl/build/ssl/libssl.a libssl_linux_amd64.syso
#	cp boringssl/build/crypto/libcrypto.a libcrypto_linux_amd64.syso
	echo "\
CREATE libquic.a
ADDLIB build/libquic.a
ADDLIB boringssl/build/ssl/libssl.a
ADDLIB boringssl/build/crypto/libcrypto.a
SAVE
END" | ar -M
fi
