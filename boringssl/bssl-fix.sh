#!/bin/bash

if ! [ -d include/boringssl ]; then
    if ! [ -d include/openssl ]; then
        echo "[-] Couldn't find openssl include dir"
        exit 1
    fi
    mv include/openssl include/boringssl
fi
# just to be sure
rm -rf include/openssl

if [ ! -f ../build/boringssl/crypto/libcrypto.a -o ! -f ../build/boringssl/ssl/libssl.a ]; then
    if ! [ -f bssl-badsyms.txt ]; then
        echo '[-] Need either bssl-badsysm.txt or existing libs - please build libquic first.'
        exit 1
    else
        echo '[+] Using bootstrap bssl-badsym.txt file'
    fi
else
    echo '[*] Finding exported symbols from previously built libraries'
    ( cat <(nm ../build/boringssl/crypto/libcrypto.a) <(nm ../build/boringssl/ssl/libssl.a) ) | grep -vE ' [A-Z] ' | grep -vE '^(      |$)' | grep -vF '.o:' | grep -vF ' r .L' | awk '{print $3}' | sed 's/^bssl_//' | sort >bssl-badsyms.txt
fi

echo '[*] Replacing QUIC openssl header includes with boringssl equivalent'
find .. -name '*.h' -print0 -o -name '*.c' -print0 -o -name '*.cc' -print0 -o -name '*.cpp' -print0 -o -name '*.S' -print0 -o -name '*.s' -print0 -o -name '*.go' -print0 \
    | xargs -0 sed -i 's#<openssl/#<boringssl/#'

echo '[*] Adding bssl.h to boringssl source files'
for f in $(find -name '*.h' -o -name '*.c' -o -name '*.cc' -o -name '*.S' -o -name '*.s'); do
    if grep -q '#include <boringssl/bssl.h>' $f; then
      continue
    fi
    cp $f mytmpf.txt;
    echo '#include <boringssl/bssl.h>' >$f
    cat mytmpf.txt >>$f
done
rm mytmpf.txt

echo '[*] Adding bssl.h to boringssl perl asm generator files'
for f in $(find -name '*.pl'); do
    if grep -q '#include <boringssl/bssl.h>' $f; then
        continue
    fi

    # FIXME: these seds don't work for all .pls, but they were sufficient for my build

    sed -i -e 's@^\.text$@.text\n#include <boringssl/bssl.h>@' \
        -e 's@^print STDOUT "#if defined(__x86_64__)\\n" if ($gas);$@print STDOUT "#include <boringssl/bssl.h>\\n" if ($gas);\nprint STDOUT "#if defined(__x86_64__)\\n" if ($gas);@' $f
done

echo '[*] Creating a header to put boringssl under a bssl prefix'
( echo '#ifndef _BSSL_H'; echo '#define _BSSL_H'; cat bssl-badsyms.txt | awk '{print "#define "$1" bssl_"$1}'; echo '#endif' ) >include/boringssl/bssl.h

echo '[*] Removing pointless noop defines in ssl.h so our redefines work'
$(dirname $0)/bssl-fix-ssl-h.py include/boringssl/ssl.h <bssl-badsyms.txt

echo '[*] Giving boringssl considerate library naming'
sed -i -e 's/^  bssl$/  bssl_test/' -e 's/(bssl /(bssl_test /' tool/CMakeLists.txt
sed -i 's/^  crypto$/  bsslcrypto/' crypto/CMakeLists.txt
sed -i 's/^  ssl$/  bssl/' ssl/CMakeLists.txt

# yes, ming
find .. -name CMakeLists.txt -print0 | xargs -0 sed -i -e 's/(crypto /(bsslcrypto /' -e 's/ crypto / bsslcrypto /' -e 's/ crypto)/ bsslcrypto)/' \
                                             -e 's/(ssl /(bssl /' -e 's/ ssl / bssl /' -e 's/ ssl)/ bssl)/'

echo '[+] Done'
