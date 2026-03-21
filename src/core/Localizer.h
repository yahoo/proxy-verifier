/** @file
 * Declaration of Localizer, the string localization class.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "case_insensitive_utils.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>
#include <vector>

#include "swoc/MemArena.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"

/** A class to handle localizing memory for strings.
 *
 * During the YAML processing stage, transactions are deserialized with their
 * strings referenced as TextViews. Common strings, such as common field names,
 * are referenced as such to save space so their memory does not exist in
 * duplicate across all transactions. The storage of this space in a single
 * location is called, in this context, localizing it. This class's functions
 * encapsulate this logic.
 */
class Localizer
{
public:
  /** Indicate that a new localization phase has started.
   *
   * This re-enables localization after a prior call to freeze_localization().
   * Existing localized strings remain valid and can continue to be referenced.
   */
  static void start_localization();

  /** Indicate that no more localization should be performed.
   *
   * All localization should be completed during the YAML parsing stage. If
   * localization happens elsewhere, then there is a logic flaw. This sets
   * state saying that localization is completed such that if localization is
   * requested elsewhere, assertions will be triggered.
   */
  static void freeze_localization();

  /** Return whether localization is currently frozen.
   *
   * This is primarily useful for tests that need to restore the prior
   * localization phase after exercising parsing helpers.
   *
   * @return True if localization is currently frozen, false otherwise.
   */
  static bool localization_is_frozen();

  static swoc::TextView localize(char const *text);
  static swoc::TextView localize_lower(char const *text);
  static swoc::TextView localize_upper(char const *text);

  static swoc::TextView localize(swoc::TextView text);
  static swoc::TextView localize_lower(swoc::TextView text);
  static swoc::TextView localize_upper(swoc::TextView text);

  /// Encoding for input text.
  enum class Encoding {
    TEXT, ///< Plain text, no encoding.
    URI   //< URI encoded.
  };

  static swoc::TextView localize(swoc::TextView text, Encoding enc);

private:
  /** A convenience boolean for the corresponding parameter to localize_helper.
   */
  enum class LocalizeFlag { None = 0, Upper = 1, Lower = 2 };

  static swoc::TextView localize_helper(swoc::TextView text, LocalizeFlag flag);
  static swoc::MemArena &get_thread_arena();

private:
  using NameSet = std::unordered_set<swoc::TextView, Hash, Hash>;
  static NameSet m_names;
  static std::shared_mutex m_names_mutex;
  static std::mutex m_arenas_mutex;
  static std::vector<std::unique_ptr<swoc::MemArena>> m_arenas;
  static std::atomic_bool m_frozen;
};
