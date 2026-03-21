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

namespace
{
thread_local swoc::MemArena *Thread_Arena = nullptr;
} // namespace

Localizer::NameSet Localizer::m_names;
std::shared_mutex Localizer::m_names_mutex;
std::mutex Localizer::m_arenas_mutex;
std::vector<std::unique_ptr<swoc::MemArena>> Localizer::m_arenas;
std::atomic_bool Localizer::m_frozen = false;

void
Localizer::start_localization()
{
  m_frozen = false;
}

swoc::MemArena &
Localizer::get_thread_arena()
{
  if (Thread_Arena != nullptr) {
    return *Thread_Arena;
  }

  std::lock_guard<std::mutex> lock(m_arenas_mutex);
  auto &arena = m_arenas.emplace_back(std::make_unique<swoc::MemArena>(8000));
  Thread_Arena = arena.get();
  return *Thread_Arena;
}

swoc::TextView
Localizer::localize_helper(TextView text, LocalizeFlag flag)
{
  assert(!m_frozen.load());
  auto &arena = get_thread_arena();
  auto span{arena.alloc(text.size()).rebind<char>()};
  if (flag == LocalizeFlag::Lower) {
    std::transform(text.begin(), text.end(), span.begin(), &tolower);
  } else if (flag == LocalizeFlag::Upper) {
    std::transform(text.begin(), text.end(), span.begin(), &toupper);
  } else {
    std::copy(text.begin(), text.end(), span.begin());
  }
  TextView local{span.data(), text.size()};
  return local;
}

void
Localizer::freeze_localization()
{
  m_frozen = true;
}

bool
Localizer::localization_is_frozen()
{
  return m_frozen.load();
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
  {
    std::shared_lock<std::shared_mutex> lock(m_names_mutex);
    auto const spot = m_names.find(text);
    if (spot != m_names.end()) {
      return *spot;
    }
  }

  auto const local = localize_helper(text, LocalizeFlag::Lower);
  std::unique_lock<std::shared_mutex> lock(m_names_mutex);
  auto const [spot, inserted] = m_names.insert(local);
  static_cast<void>(inserted);
  return *spot;
}

swoc::TextView
Localizer::localize_upper(TextView text)
{
  // m_names.find() does a case insensitive lookup, so cache lookup via
  // m_names only should be used for case-insensitive localization. It's
  // value applies to well-known, common strings such as HTTP headers.
  {
    std::shared_lock<std::shared_mutex> lock(m_names_mutex);
    auto const spot = m_names.find(text);
    if (spot != m_names.end()) {
      return *spot;
    }
  }

  auto const local = localize_helper(text, LocalizeFlag::Upper);
  std::unique_lock<std::shared_mutex> lock(m_names_mutex);
  auto const [spot, inserted] = m_names.insert(local);
  static_cast<void>(inserted);
  return *spot;
}

swoc::TextView
Localizer::localize(TextView text, Encoding enc)
{
  assert(!m_frozen.load());
  if (Encoding::URI == enc) {
    auto &arena = get_thread_arena();
    auto span{arena.require(text.size()).remnant().rebind<char>()};
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
    arena.alloc(text.size());
    return text;
  }
  return localize(text);
}
