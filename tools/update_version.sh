#!/usr/bin/env bash

set -e

usage="usage: $(basename $0) <new_version_name>"

fail()
{
  echo $1
  exit 1
}
[ $# -eq 1 ] || fail "${usage}"
new_version="$1"

[[ "${new_version}" == v* ]] && new_version=$(echo ${new_version} | sed 's/v//g')

script_dir=$(dirname $0)

parts_file="${script_dir}/../local/parts/proxy-verifier.part"
[ -f "${parts_file}" ] || fail "Could not find proxy-verifier.part. Tried: \"${parts_file}\""
[ -r "${parts_file}" -a -w "${parts_file}" ] || fail "\"${parts_file}\" is not readable and writeable"

src_file="${script_dir}/../local/include/core/ArgParser.h"
[ -f "${src_file}" ] || fail "Could not find ArgParser.h. Tried: \"${src_file}\""
[ -r "${src_file}" -a -w "${src_file}" ] || fail "\"${src_file}\" is not readable and writeable"

# Make sure we are in the git repo. The user may have executed this from
# outside of it.
cd ${script_dir}
old_version=$(\
  git for-each-ref --sort=creatordate refs/tags | \
  awk '/refs\/tags\/v/ {print $NF}' | \
  tail -1 | \
  sed 's:refs/tags/v::g')

# Go back: the file paths are relative to the user's current working directory.
cd - 2>&1 > /dev/null
sed -i='' "s/${old_version}/${new_version}/g" "${parts_file}"
sed -i='' "s/${old_version}/${new_version}/g" "${src_file}"

echo "Do not forget to run the \"version_argument\" AuTest."
