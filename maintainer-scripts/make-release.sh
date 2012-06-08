#!/bin/bash

if [ ! -f Lib/yubico/yubikey.py ]; then
    echo "$0: Must be executed from top python-yubico dir."
    exit 1
fi

do_test="true"
do_sign="true"

if [ "x$1" == "x--no-test" ]; then
    do_test="false"
    shift
fi

if [ "x$1" == "x--no-sign" ]; then
    do_sign="false"
    shift
fi

gitref="$1"

if [ "x$gitref" = "x" ]; then
    echo "Syntax: $0 [--no-test] [--no-sign] gitref"
    exit 1
fi

tmpdir=$(mktemp -d /tmp/python-yubico_make-release.XXXXXX)
if [ ! -d "$tmpdir" ]; then
    echo "$0: Failed creating tmpdir ($tmpdir)"
    exit 1
fi


set -e

gitdesc=$(git describe $gitref)

setup_ver=$(grep version setup.py | awk -F \' '{print $2}')
if [ "x$setup_ver" != "x$gitdesc" ]; then
    echo ""
    echo "setup.py version mismatch! ($setup_ver != $gitdesc) Press enter to ignore."
    read foo
fi

init_ver=$(grep __version__ Lib/yubico/__init__.py | awk -F \' '{print $2}')
if [ "x$init_ver" != "x$gitdesc" ]; then
    echo ""
    echo "Lib/yubico/__init__.py version mismatch! ($init_ver != $gitdesc) Press enter to ignore."
    read foo
fi

releasedir="python-yubico-$gitdesc"
tarfile="$tmpdir/$releasedir.tar"
git archive --format=tar --prefix=${releasedir}/ ${gitref} | (cd $tmpdir && tar xf -)

git2cl > $tmpdir/$releasedir/ChangeLog

echo "path : $tmpdir/$releasedir"

ls -l $tmpdir/$releasedir

# tar it up to not accidentally get junk in there while running tests etc.
(cd ${tmpdir} && tar zcf python-yubico-${gitdesc}.tar.gz ${releasedir})

if [ "x$do_test" != "xfalse" ]; then
    # run all unit tests
    (cd $tmpdir/$releasedir && PYTHONPATH="Lib" ./Tests/run.sh)
fi

mkdir -p ../releases
cp ${tmpdir}/python-yubico-${gitdesc}.tar.gz ../releases

if [ "x$do_sign" != "xfalse" ]; then
    # sign the release
    gpg --detach-sign ../releases/python-yubico-${gitdesc}.tar.gz
    gpg --verify ../releases/python-yubico-${gitdesc}.tar.gz.sig
fi

echo ""
echo "Finished"
echo ""
ls -l ../releases/python-yubico-${gitdesc}.tar.gz*
