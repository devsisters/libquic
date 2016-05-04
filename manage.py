#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import json

from getdep import DependencyTree


SRCROOT = "src"


def open_deps(filepath="DEPS"):
    with open(filepath, "r") as f:
        s = f.read()
        if "# START #" not in s:
            print("Cannot parse DEPS")
            exit(1)
        try:
            return json.loads(s.split("# START #")[1].strip())
        except ValueError:
            print("Cannot parse DEPS")
            exit(1)


def run(cmd):
    print(cmd)
    r = os.system(cmd)
    if r != 0:
        print("Script '{}' failed with error code {}. Exiting".format(cmd, r))
        exit(r)


def force_run(cmd):
    print(cmd)
    r = os.system(cmd)
    if r != 0:
        print("Script '{}' failed with error code {}. Continuing anyway...".format(cmd, r))


def main():
    deps = open_deps()
    without_patches = False
    if sys.argv[2] == "--without-patches":
        without_patches = True
        chromium_root = os.path.abspath(sys.argv[3])
    else:
        chromium_root = os.path.abspath(sys.argv[2])

    # 1. Clean old files
    run("rm -rf src/* obj/* boringssl/build")

    # 2. Copy files from chromium upstream
    dirs = set()
    files = set()

    common_exclude = set(deps.get("automatic_dependency_common_exclude", []))
    unused_common_exclude = set(deps.get("automatic_dependency_common_exclude", []))

    for autodep in deps.get("automatic_dependency", []):
        tree = DependencyTree(chromium_root, common_exclude | set(autodep.get("exclude", [])), True)
        depmap = tree.get_dependencies(autodep["from"])
        unused_common_exclude &= (tree.excludes - tree.excludes_used)

        for node in depmap.keys():
            dirpath = os.path.join("src", os.path.dirname(node))
            if dirpath not in dirs:
                run("mkdir -p {}".format(dirpath))
                dirs.add(dirpath)

            if node not in files:
                run("cp {} src/{}".format(tree.realpath(node), node))
                files.add(node)

    if unused_common_exclude:
        print("Warning: following common excludes are not used")
        print(" - " + "\n - ".join(unused_common_exclude))

    for dep in deps.get("manual_dependency", []):
        if dep["action"] == "makedir":
            for target in dep["target"]:
                run("mkdir -p {srcroot}/{target}".format(srcroot=SRCROOT, target=target))
        elif dep["action"] == "copy":
            for target in dep["target"]:
                run("cp {chromium}/{target} {srcroot}/{targetpath}/".format(
                    chromium=chromium_root,
                    srcroot=SRCROOT,
                    target=target,
                    targetpath=os.path.dirname(target)))
        elif dep["action"] == "copydir":
            for target in dep["target"]:
                run("cp -r {chromium}/{target} {srcroot}/{targetpath}/".format(
                    chromium=chromium_root,
                    srcroot=SRCROOT,
                    target=target,
                    targetpath=os.path.dirname(target)))
        elif dep["action"] == "remove":
            for target in dep["target"]:
                run("rm -f {0}".format(target))

    # 3. Apply patch
    if without_patches:
        print("Skipping patches...")
    else:
        for patch in deps.get("patches", []):
            force_run("patch -p1 < {0}".format(patch))

    # 4. Copy custom files
    for custom in deps.get("custom_files", []):
        run("cp {from_} {srcroot}/{to}".format(from_=custom['from'], to=custom['to'], srcroot=SRCROOT))


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "sync":
        print("Run `./manage.py sync <CHROMIUM ROOT>`")
        exit(1)
    main()
