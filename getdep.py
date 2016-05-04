#!/usr/bin/env python
# Dependency Tracker for C++ source tree
# Warning: This program do not understand any preprocessors and macros.
# And this program cannot track the dependendy if the header's name and source's name are different.
# (net_util.h <-\-> net_util_posix.cc)
#
# You may use `exclude` option to leave out unwanted dependency.
from __future__ import print_function

import os
import argparse


class DependencyTree(object):
    def __init__(self, root, excludes, debug=False):
        self.root = root
        self.excludes = set(excludes) if excludes else set()
        self.excludes_used = set()
        self.debug = debug

    def get_dependencies(self, target):
        depmap = {}
        wherefrom = {}
        q = []
        vis = set()

        def enq(new, now):
            if new in self.excludes:
                self.excludes_used.add(new)
                return

            if new not in vis:
                vis.add(new)
                q.append(new)
                depmap[new] = []
                wherefrom[new] = now

        enq(target, None)

        while q:
            now = q.pop(0)

            if self.debug:
                n = now
                print("  [ ", end=" ")
                while n:
                    print(n, " => ", end=" ")
                    n = wherefrom[n]
                print(" ]")

            if now.endswith(".h") and os.path.exists(self.realpath(now[:-1] + 'cc')):
                enq(now[:-1] + 'cc', now)
                depmap[now].append(now[:-1] + 'cc')

            if now.endswith(".h") and os.path.exists(self.realpath(now[:-1] + 'mm')):
                enq(now[:-1] + 'mm', now)
                depmap[now].append(now[:-1] + 'mm')

            for dependency in self.parse_cc(now):
                enq(dependency, now)
                # print now, dependency
                depmap[now].append(dependency)

        return depmap

    def critical_node(self, target):
        depmap = self.get_dependencies(target)
        N = len(depmap)
        M = sum(map(len, depmap.values()))
        results = []
        origin_nodes = set(depmap.keys())

        original_exc = self.excludes

        for key in depmap.keys():
            if key.endswith(".h"):
                self.excludes = original_exc.copy()
                self.excludes.add(key)
                self.excludes.add(key[:-1] + "cc")

                depmap_cut = self.get_dependencies(target)
                results.append((N - len(depmap_cut), M - sum(map(len, depmap_cut.values())), key,
                                origin_nodes - set(depmap_cut.keys())))

        results.sort()

        print(N, M)
        return results

    def realpath(self, path):
        if ".pb." in path:
            path = "out/Debug/gen/protoc_out/" + path
        return os.path.join(self.root, path)

    def parse_cc(self, source):
        r = []
        with open(self.realpath(source), "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#include") and '"' in line:
                    fname = line.split('"')[1]
                    r.append(fname)

        return r


def main():
    parser = argparse.ArgumentParser(description="C++ Dependency Tracker for chromium")
    parser.add_argument("srcroot", type=str)
    parser.add_argument("target", type=str)
    parser.add_argument("--exclude", action="append")
    parser.add_argument("--dot", action="store_true")
    parser.add_argument("--cmd", action="store_true")
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()
    tree = DependencyTree(args.srcroot, args.exclude, args.debug)
    depmap = tree.get_dependencies(args.target)

    if args.dot:
        print("""\
digraph "source tree" {
    overlap=scale;
    size="8,10";
    ratio="fill";
    fontsize="16";
    fontname="Helvetica";
    clusterrank="local";
""")
        for node in depmap.keys():
            if "quic" in node:
                node1 = node.rstrip(".cc").rstrip(".h")
                print('    "{0}" [label="{0}", style="filled", color="red"]'.format(node1))

        vis = set()
        for f, deps in depmap.iteritems():
            for dep in deps:
                f1 = f.rstrip(".cc").rstrip(".h")
                dep1 = dep.rstrip(".cc").rstrip(".h")

                if (f1, dep1) not in vis:
                    vis.add((f1, dep1))
                    print("    \"{}\" -> \"{}\"".format(f1, dep1))
        print("}")

    if args.cmd:
        dirs = set()
        for node in depmap.keys():
            dirpath = os.path.join("src", os.path.dirname(node))
            if dirpath not in dirs:
                print("mkdir -p {}".format(dirpath))
                dirs.add(dirpath)
            print("cp {} src/{}".format(tree.realpath(node), node))


if __name__ == "__main__":
    main()
