/** @file
 * Definition of Localizer.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/Localizer.h"

#include <algorithm>
#include <cassert>
#include <vector>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

Localizer::NameSet Localizer::m_names;
swoc::MemArena Localizer::m_arena{8000};
bool Localizer::m_frozen = false;

swoc::TextView
Localizer::localize_helper(TextView text, LocalizeFlag flag)
{
  assert(!m_frozen);
  auto span{m_arena.alloc(text.size()).rebind<char>()};
  if (flag == LocalizeFlag::Lower) {
    std::transform(text.begin(), text.end(), span.begin(), &tolower);
  } else if (flag == LocalizeFlag::Upper) {
    std::transform(text.begin(), text.end(), span.begin(), &toupper);
  } else {
    std::copy(text.begin(), text.end(), span.begin());
  }
  TextView local{span.data(), text.size()};
  if (flag == LocalizeFlag::Lower || flag == LocalizeFlag::Upper) {
    m_names.insert(local);
  }
  return local;
}

void
Localizer::freeze_localization()
{
  m_frozen = true;
}

swoc::TextView
Localizer::localize(char const *text)
{
  return localize_helper(TextView{text, strlen(text) + 1}, LocalizeFlag::None);
}

swoc::TextView
Localizer::localize_lower(char const *text)
{
  return localize_lower(TextView{text, strlen(text) + 1});
}

swoc::TextView
Localizer::localize_upper(char const *text)
{
  return localize_upper(TextView{text, strlen(text) + 1});
}

swoc::TextView
Localizer::localize(TextView text)
{
  return localize_helper(text, LocalizeFlag::None);
}

swoc::TextView
Localizer::localize_lower(TextView text)
{
  // m_names.find() does a case insensitive lookup, so cache lookup via
  // m_names only should be used for case-insensitive localization. It's
  // value applies to well-known, common strings such as HTTP headers.
  auto spot = m_names.find(text);
  if (spot != m_names.end()) {
    return *spot;
  }
  return localize_helper(text, LocalizeFlag::Lower);
}

swoc::TextView
Localizer::localize_upper(TextView text)
{
  // m_names.find() does a case insensitive lookup, so cache lookup via
  // m_names only should be used for case-insensitive localization. It's
  // value applies to well-known, common strings such as HTTP headers.
  auto spot = m_names.find(text);
  if (spot != m_names.end()) {
    return *spot;
  }
  return localize_helper(text, LocalizeFlag::Upper);
}

swoc::TextView
Localizer::localize(TextView text, Encoding enc)
{
  assert(!m_frozen);
  if (Encoding::URI == enc) {
    auto span{m_arena.require(text.size()).remnant().rebind<char>()};
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
    m_arena.alloc(text.size());
    return text;
  }
  return localize(text);
}
