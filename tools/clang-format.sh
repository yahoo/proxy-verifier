#! /usr/bin/env bash
#
#  Simple wrapper to run clang-format on a bunch of files
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

# Update the PKGDATE with the new version date when making a new clang-format binary package.
PKGDATE="20180413"

function main() {
  set -e # exit on error
  ROOT=${ROOT:-$(cd $(dirname $0) && git rev-parse --show-toplevel)/.git/fmt/${PKGDATE}}

  DIR=${1:-.}
  PACKAGE="clang-format-${PKGDATE}.tar.bz2"
  VERSION="clang-format version 6.0.1 (http://llvm.org/git/clang.git d5f48a217f404c3462537527f4169bb45eed3904) (http://llvm.org/git/llvm.git aa0c91ae818e0b9e7981a42236dededc85997568)"

  URL=${URL:-https://ci.trafficserver.apache.org/bintray/${PACKAGE}}

  TAR=${TAR:-tar}
  CURL=${CURL:-curl}

  # default to using native sha1sum command when available
  if [ $(which sha1sum) ] ; then
    SHASUM=${SHASUM:-sha1sum}
  else
    SHASUM=${SHASUM:-shasum}
  fi

  ARCHIVE=$ROOT/$(basename ${URL})

  case $(uname -s) in
  Darwin)
    FORMAT=${FORMAT:-${ROOT}/clang-format/clang-format.osx}
    ;;
  Linux)
    FORMAT=${FORMAT:-${ROOT}/clang-format/clang-format.linux}
    ;;
  *)
    echo "Leif needs to build a clang-format for $(uname -s)"
    exit 2
  esac

  mkdir -p ${ROOT}

  # Note that the two spaces between the hash and ${ARCHIVE) is needed
  if [ ! -e ${FORMAT} -o ! -e ${ROOT}/${PACKAGE} ] ; then
    ${CURL} -L --progress-bar -o ${ARCHIVE} ${URL}
    ${TAR} -x -C ${ROOT} -f ${ARCHIVE}
    cat > ${ROOT}/sha1 << EOF
26aff1bc6dc315c695c62cadde38c934acd22d06  ${ARCHIVE}
EOF
    ${SHASUM} -c ${ROOT}/sha1
    chmod +x ${FORMAT}
  fi


  # Make sure we only run this with our exact version
  ver=$(${FORMAT} --version)
  if [ "$ver" != "$VERSION" ]; then
      echo "Wrong version of clang-format!"
      echo "See https://bintray.com/apache/trafficserver/clang-format-tools/view for a newer version,"
      echo "or alternatively, undefine the FORMAT environment variable"
      exit 1
  else
      for file in $(find $DIR -iname \*.[ch] -o -iname \*.cc); do
    echo $file
    ${FORMAT} -i $file
      done
  fi
}

if [[ "$(basename -- "$0")" == 'clang-format.sh' ]]; then
  main "$@"
else
  ROOT=${ROOT:-$(git rev-parse --show-toplevel)/.git/fmt/${PKGDATE}}
fi
