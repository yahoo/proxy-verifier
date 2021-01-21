/** @file
 * Data structures to support case-insensitive containers.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <strings.h>

#include "swoc/ext/HashFNV.h"
#include "swoc/TextView.h"

/** Case-insensitive hashing function. */
struct Hash
{
  swoc::Hash64FNV1a::value_type
  operator()(swoc::TextView view) const
  {
    return swoc::Hash64FNV1a{}.hash_immediate(swoc::transform_view_of(&tolower, view));
  }
  bool
  operator()(swoc::TextView const &lhs, swoc::TextView const &rhs) const
  {
    return 0 == strcasecmp(lhs, rhs);
  }
};

/** Case-insensitive comparison function. */
struct CaseInsensitiveCompare
{
  bool
  operator()(swoc::TextView const &lhs, swoc::TextView const &rhs) const
  {
    return strcasecmp(lhs, rhs) < 0;
  }
};
