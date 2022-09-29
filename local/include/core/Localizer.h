/** @file
 * Declaration of Localizer, the string localization class.
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "case_insensitive_utils.h"

#include <unordered_set>

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
  /** Indicate that no more localization should be performed.
   *
   * All localization should be completed during the YAML parsing stage. If
   * localization happens elsewhere, then there is a logic flaw. This sets
   * state saying that localization is completed such that if localization is
   * requested elsewhere, assertions will be triggered.
   */
  static void freeze_localization();

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

private:
  using NameSet = std::unordered_set<swoc::TextView, Hash, Hash>;
  static NameSet _names;
  static swoc::MemArena _arena;
  static bool _frozen;
};
