#!/usr/bin/env python

# stdin is a list of symbols that boringssl has naughtily appropriated
# and potentially changed the semantics for
#
# separately, openssl decided to make ifdefs for some of their symbols
# that were previously macros, so we need to fix that first
#
# this program removes the pointless openssl defines
#
# some of them are multi-line and there are many, so sed is too slow/fiddly

import sys
import re

header = open(sys.argv[1]).read()

for line in sys.stdin:
    line = line.strip()
    header = re.sub(r'^#define {0}(\s\\\n)?\s+{1}$'.format(line, line), '', header, flags=re.MULTILINE)

open(sys.argv[1], 'w').write(header)
