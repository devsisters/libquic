import os
import sys
import argparse
import subprocess
import collections


def main():
    parser = argparse.ArgumentParser(description="Copy files from chromium project")
    parser.add_argument('src path', help='Chromium source root path', type=str,)
    subprocess.Popen("cinclude2dots", stdout=subprocess.PIPE, cwd=os.path.abspath(""))


f = open(sys.argv[1], "r")
g = collections.OrderedDict()
vis = set()

for line in f:
    if " -> " not in line:
        continue
    source, target = line.split(" -> ")

    source = source.strip()[1:-1]
    target = target.strip()[1:-1]

    if source not in g:
        g[source] = []

    g[source].append(target)


initial_source = sys.argv[2]
q = [initial_source]
vis.add(initial_source)

rootdir = os.path.abspath(os.path.dirname(__file__))
mkdirvis = set()

while q:
    now = q.pop(0)

    if os.path.dirname(now) not in mkdirvis:
        print ("mkdir -p {}/src/{}").format(rootdir, os.path.dirname(now))
        mkdirvis.add(os.path.dirname(now))
    print ("cp /home/hodduc/repos/chromium/src/{} {}/src/{}".format(now, rootdir, now))
    print ("cp /home/hodduc/repos/chromium/src/{} {}/src/{}".format(now[:-1]+"cc", rootdir, now[:-1]+"cc"))

    if now not in g:
        continue

    # DOT repr
#    for endpt in g[now]:
#        print '"{}" -> "{}"'.format(now, endpt)

#    print now, ":", g[now]
    for nxt in g[now]:
        if nxt not in vis:
            if "net_util.h" in now and "network_change_notifier.h" in nxt:
                continue
            q.append(nxt)
            vis.add(nxt)
