#!/usr/bin/env python3
import os
import json
import argparse

from cpp import PreProcessor


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
    parser = argparse.ArgumentParser(description="libquic sync tool w/ chromium")
    parser.add_argument("chromium_root", type=str)
    parser.add_argument("--patch", action="store_true")

    args = parser.parse_args()

    chromium_root = os.path.abspath(args.chromium_root)

    # 1. Clean old files
    run("rm -rf src/* obj/* boringssl/build")

    # 2. Copy files from chromium upstream
    dirs = set()
    files = set()

    excludes = [os.path.join(chromium_root, x) for x in deps.get("dependency_exclude", [])]

    processor = PreProcessor(chromium_root, dict={'OS_POSIX': 1, 'OS_MAXOSX': 1, 'OS_OPENBSD': 1, 'OS_ANDROID': 1, 'OS_LINUX': 1}, excludes=excludes)

    q = deps.get("automatic_dependency", [])
    while q:
        autodep = q.pop()
        print("Tracking dependencies of {}".format(autodep))

        depends = [os.path.join(chromium_root, autodep)] + processor(os.path.join(chromium_root, autodep))

        for node in depends:
            if node.startswith(chromium_root):
                relpath = os.path.join("src", node[len(chromium_root)+1:])
            else:
                relpath = node

            dirpath = os.path.dirname(relpath)
            if dirpath not in dirs:
                run("mkdir -p {}".format(dirpath))
                dirs.add(dirpath)

            if relpath not in files:
                run("cp -p {} {}".format(node, relpath))
                files.add(relpath)

                if node.endswith('.h'):
                    for extension in ('.cc', '.mm', '_posix.cc', '_mac.mm', '_mac.cc', '_linux.cc', '_freebsd.cc'):
                        if os.path.exists(node[:-2] + extension):
                            print("Append {} from {}".format(node[:-2] + extension, autodep))
                            q.append(node[:-2] + extension)

    for dep in deps.get("manual_dependency", []):
        if dep["action"] == "makedir":
            for target in dep["target"]:
                run("mkdir -p src/{target}".format(target=target))
        elif dep["action"] == "copy":
            for target in dep["target"]:
                run("cp -p {chromium}/{target} src/{targetpath}/".format(
                    chromium=chromium_root,
                    target=target,
                    targetpath=os.path.dirname(target)))
        elif dep["action"] == "copydir":
            for target in dep["target"]:
                run("cp -p -r {chromium}/{target} src/{targetpath}/".format(
                    chromium=chromium_root,
                    target=target,
                    targetpath=os.path.dirname(target)))
        elif dep["action"] == "remove":
            for target in dep["target"]:
                run("rm -f {0}".format(target))

    # 3. Apply patch
    if args.patch:
        for patch in deps.get("patches", []):
            force_run("patch -p1 < {0}".format(patch))
    else:
        print("Skipping patches...")

    # 4. Copy custom files
    for custom in deps.get("custom_files", []):
        run("cp -p {from_} src/{to}".format(from_=custom['from'], to=custom['to']))


if __name__ == "__main__":
    main()
