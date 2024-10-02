/** @file
 * Common data structures and definitions for Proxy Verifier tools.
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <condition_variable>
#include <deque>
#include <list>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>

#include "swoc/BufferWriter.h"
#include "swoc/Errata.h"
#include "swoc/TextView.h"
#include "swoc/bwf_base.h"
#include "swoc/swoc_ip.h"

extern bool Verbose;

constexpr swoc::Errata::Severity S_DIAG{1};
constexpr swoc::Errata::Severity S_INFO{2};
constexpr swoc::Errata::Severity S_WARN{3};
constexpr swoc::Errata::Severity S_ERROR{4};

/** Configure the process to block SIGPIPE.
 *
 * Unless we block SIGPIPE, the process abruptly stops if SSL_write triggers
 * the signal if the peer drops the connection before we write to the socket.
 * This results in an abrupt termination of the process. SSL_write will return
 * a -1 in these circumstances if the SIGPIPE doesn't interrupt it, so even
 * with the signal blocked we will still report the issue and continue
 * gracefully if SIGPIPE is raised under these circumstances.
 *
 * @return 0 on success, non-zero on failure.
 */
swoc::Rv<int> block_sigpipe();

/** Configure logging.
 *
 * @param[in] verbose_argument The user-specified verbosity requested.
 */
swoc::Errata configure_logging(const std::string_view verbose_argument);

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &bwformat(BufferWriter &w, bwf::Spec const &spec, std::chrono::milliseconds const &s);
} // namespace SWOC_VERSION_NS
} // namespace swoc

/** Parse the given address into an IPEndpoint.
 *
 * @param[in] addresses The comman separated addresss to parse, such as:
 * "127.0.0.1:8081".
 *
 * @param[out] targets The parsed addresses as IPEndpoint objects.
 */
swoc::Errata parse_ips(std::string addresses, std::deque<swoc::IPEndpoint> &targets);

/** Parse the given hostname into an IPEndpoint.
 *
 * @param[in] hostnames The comma separated hostnames to parse, such as:
 * "test.machine.com:8081".
 * @param[out] targets The resolved hostnames as IPEndpoint objects.
 *
 * @return The parsed endpoint.
 */
swoc::Errata resolve_ips(std::string hostnames, std::deque<swoc::IPEndpoint> &targets);
swoc::Rv<swoc::IPEndpoint> Resolve_FQDN(swoc::TextView host);

class ThreadInfo
{
public:
  std::thread *_thread = nullptr;
  std::condition_variable _data_ready_cvar;
  std::mutex _data_ready_mutex;
  virtual bool data_ready() = 0;
};

// This must be a list so that iterators / pointers to elements do not go stale.
class ThreadPool
{
public:
  void wait_for_work(ThreadInfo *info);
  ThreadInfo *get_worker();
  virtual std::thread make_thread(std::thread *) = 0;
  void join_threads();
  static constexpr size_t default_max_threads = 2'000;
  void set_max_threads(size_t new_max);
  size_t get_max_threads() const;

protected:
  /// Any thread that has been created for the ThreadPool.
  std::list<std::thread> _allThreads;

  /// The subset of @a _allThreads that are currently available to do work.
  std::deque<ThreadInfo *> _idleThreads;
  std::condition_variable _idleThreadsCvar;
  std::mutex _idleThreadsMutex;
  size_t max_threads = default_max_threads;
};
