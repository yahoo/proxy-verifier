/** @file
 * Definition of Localizer.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/Localizer.h"

#include <cassert>
#include <dirent.h>
#include <thread>
#include <vector>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/bwf_std.h"

using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

Localizer::NameSet Localizer::_names;
swoc::MemArena Localizer::_arena{8000};
bool Localizer::_frozen = false;

swoc::TextView
Localizer::localize_helper(TextView text, bool should_lower)
{
  assert(!_frozen);
  auto span{_arena.alloc(text.size()).rebind<char>()};
  if (should_lower) {
    std::transform(text.begin(), text.end(), span.begin(), &tolower);
  } else {
    std::copy(text.begin(), text.end(), span.begin());
  }
  TextView local{span.data(), text.size()};
  if (should_lower) {
    _names.insert(local);
  }
  return local;
}

void
Localizer::freeze_localization()
{
  _frozen = true;
}

swoc::TextView
Localizer::localize(char const *text)
{
  return localize_helper(TextView{text, strlen(text) + 1}, !SHOULD_LOWER);
}

swoc::TextView
Localizer::localize_lower(char const *text)
{
  return localize_lower(TextView{text, strlen(text) + 1});
}

swoc::TextView
Localizer::localize(TextView text)
{
  return localize_helper(text, !SHOULD_LOWER);
}

swoc::TextView
Localizer::localize_lower(TextView text)
{
  // _names.find() does a case insensitive lookup, so cache lookup via
  // _names only should be used for case-insensitive localization. It's
  // value applies to well-known, common strings such as HTTP headers.
  auto spot = _names.find(text);
  if (spot != _names.end()) {
    return *spot;
  }
  return localize_helper(text, SHOULD_LOWER);
}

swoc::TextView
Localizer::localize(TextView text, Encoding enc)
{
  assert(!_frozen);
  if (Encoding::URI == enc) {
    auto span{_arena.require(text.size()).remnant().rebind<char>()};
    auto spot = text.begin(), limit = text.end();
    char *dst = span.begin();
    while (spot < limit) {
      if (*spot == '%' &&
          (spot + 1 < limit && isxdigit(spot[1]) && (spot + 2 < limit && isxdigit(spot[2]))))
      {
        *dst++ = swoc::svto_radix<16>(TextView{spot + 1, spot + 3});
        spot += 3;
      } else {
        *dst++ = *spot++;
      }
    }
    TextView text{span.data(), dst};
    _arena.alloc(text.size());
    return text;
  }
  return localize(text);
}
