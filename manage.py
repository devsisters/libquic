#!/usr/bin/env python
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
    print cmd
    r = os.system(cmd)
    if r != 0:
        exit(r)


def main():
    deps = open_deps()
    chromium_root = os.path.abspath(sys.argv[2])

    # 1. Clean old files
    run("rm -rf src/* obj/* boringssl/build")

    # 2. Copy files from chromium upstream
    dirs = set()
    files = set()

    for autodep in deps.get("automatic_dependency", []):
        tree = DependencyTree(chromium_root, autodep["exclude"], False)
        depmap = tree.get_dependencies(autodep["from"])

        for node in depmap.keys():
            dirpath = os.path.join("src", os.path.dirname(node))
            if dirpath not in dirs:
                run("mkdir -p {}".format(dirpath))
                dirs.add(dirpath)

            if node not in files:
                run("cp {} src/{}".format(tree.realpath(node), node))
                files.add(node)

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
        elif dep["action"] == "remove":
            for target in dep["target"]:
                run("rm -f {0}".format(target))

    # 3. Apply patch
    for patch in deps.get("patches", []):
        run("patch -p1 < {0}".format(patch))

    # 4. Copy custom files
    for custom in deps.get("custom_files", []):
        run("cp {from_} {srcroot}/{to}".format(from_=custom['from'], to=custom['to'], srcroot=SRCROOT))


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "sync":
        print("Run `./manage.py sync <CHROMIUM ROOT>`")
        exit(1)
    main()
