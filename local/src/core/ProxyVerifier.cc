/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2022, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/ProxyVerifier.h"
#include "core/verification.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sstream>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string>
#include <thread>
#include <unistd.h>

#include "swoc/IPSrv.h"
#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;

namespace chrono = std::chrono;
using chrono::milliseconds;

bool Verbose = false;

static std::array<swoc::TextView, 5> S_NAMES = {"Success", "DEBUG", "INFO", "WARNING", "ERROR"};

const bool ERRATA_LIB_INIT = []() -> bool {
  swoc::Errata::SEVERITY_NAMES =
      swoc::MemSpan<swoc::TextView const>{S_NAMES.data(), S_NAMES.size()};
  swoc::Errata::DEFAULT_SEVERITY = S_INFO;
  swoc::Errata::FAILURE_SEVERITY = S_WARN;
  return true;
}();

swoc::Rv<int>
block_sigpipe()
{
  swoc::Rv<int> zret = 0;
  sigset_t set;
  if (sigemptyset(&set)) {
    zret = -1;
    zret.note(S_ERROR, R"(Could not empty the signal set: {})", swoc::bwf::Errno{});
  } else if (sigaddset(&set, SIGPIPE)) {
    zret = -1;
    zret.note(S_ERROR, R"(Could not add SIGPIPE to the signal set: {})", swoc::bwf::Errno{});
  } else if (pthread_sigmask(SIG_BLOCK, &set, nullptr)) {
    zret = -1;
    zret.note(S_ERROR, R"(Could not block SIGPIPE: {})", swoc::bwf::Errno{});
  }
  return zret;
}

swoc::Errata
configure_logging(const std::string_view verbose_argument)
{
  swoc::Errata errata{};
  auto severity_cutoff = S_INFO;
  if (strcasecmp(verbose_argument, "error") == 0) {
    severity_cutoff = S_ERROR;
  } else if (strcasecmp(verbose_argument, "warn") == 0) {
    severity_cutoff = S_WARN;
  } else if (strcasecmp(verbose_argument, "info") == 0) {
    severity_cutoff = S_INFO;
  } else if (
      strcasecmp(verbose_argument, "debug") == 0 || strcasecmp(verbose_argument, "diag") == 0) {
    severity_cutoff = S_DIAG;
  } else {
    errata.note(S_ERROR, "Unrecognized verbosity parameter: {}", verbose_argument);
    return errata;
  }
  // Note: FILTER_SEVERITY is nice as it will actually filter the messages at
  // the point that note() is called, not at the time when it is later emitted.
  swoc::Errata::FILTER_SEVERITY = severity_cutoff;
  errata.note(S_DIAG, "Configured logging at level {}", severity_cutoff);

  static std::mutex logging_mutex;

  swoc::Errata::register_sink([severity_cutoff](Errata const &errata) {
    if (errata.severity() < severity_cutoff) {
      return;
    }
    for (auto const &annotation : errata) {
      if (!annotation.has_severity()) {
        std::cerr << "Runtime error: an annotation without a severity: " << annotation.text()
                  << std::endl;
        continue;
      }
      std::ostringstream log_line;
      log_line << std::string(annotation.level() * 2, ' ') << "[" << S_NAMES[annotation.severity()]
               << "]: " << annotation.text();
      {
        std::lock_guard<std::mutex> lock(logging_mutex);
        std::cout << log_line.str() << std::endl;
      }
    }
  });
  return errata;
}

namespace swoc
{
inline namespace SWOC_VERSION_NS
{
BufferWriter &
bwformat(BufferWriter &w, bwf::Spec const & /* spec */, milliseconds const &s)
{
  w.print("{} milliseconds", s.count());
  return w;
}
} // namespace SWOC_VERSION_NS
} // namespace swoc

swoc::Errata
parse_ips(std::string addresses, std::deque<swoc::IPEndpoint> &targets)
{
  swoc::Errata errata;
  size_t offset = 0;
  size_t new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = addresses.find(',', offset);
    std::string name = addresses.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    swoc::IPEndpoint addr;
    if (!addr.parse(name)) {
      errata.note(S_ERROR, R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    targets.push_back(addr);
  }
  return errata;
}

swoc::Errata
resolve_ips(std::string hostnames, std::deque<swoc::IPEndpoint> &targets)
{
  swoc::Errata errata;
  size_t offset = 0;
  size_t new_offset = 0;
  while (offset != std::string::npos) {
    new_offset = hostnames.find(',', offset);
    std::string name = hostnames.substr(offset, new_offset - offset);
    offset = new_offset != std::string::npos ? new_offset + 1 : new_offset;
    auto &&[tmp_target, result] = Resolve_FQDN(name);
    if (!result.is_ok()) {
      errata.note(S_ERROR, R"("{}" is not a valid IP address.)", name);
      return errata;
    }
    targets.push_back(tmp_target);
  }
  return errata;
}

swoc::Rv<swoc::IPEndpoint>
Resolve_FQDN(swoc::TextView fqdn)
{
  swoc::Rv<swoc::IPEndpoint> zret;
  swoc::TextView host_str, port_str;
  in_port_t port = 0;
  static constexpr in_port_t MAX_PORT{std::numeric_limits<in_port_t>::max()};

  if (swoc::IPEndpoint::tokenize(fqdn, &host_str, &port_str)) {
    swoc::IPAddr addr;
    if (port_str) {
      swoc::TextView text(port_str);
      auto n = swoc::svto_radix<10>(text);
      if (text.empty() && 0 < n && n <= MAX_PORT) {
        port = n;
        if (addr.load(host_str)) {
          zret.result().assign(swoc::IPSrv{addr, port});
        } else {
          addrinfo *addrs = nullptr;
          addrinfo hints;
          char buff[host_str.size() + 1];
          memcpy(buff, host_str.data(), host_str.size());
          buff[host_str.size()] = '\0';
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          hints.ai_flags = 0;
          auto result = getaddrinfo(buff, nullptr, &hints, &addrs);
          if (0 == result) {
            zret.result().assign(swoc::IPSrv{addrs->ai_addr});
            zret.result().network_order_port() = htons(port);
            freeaddrinfo(addrs);
          } else {
            zret.note(
                S_ERROR,
                R"(Failed to resolve "{}": {}.)",
                host_str,
                swoc::bwf::Errno(result));
          }
        }
      } else {
        zret.note(S_ERROR, R"(Port value {} out of range [ 1 .. {} ].)", port_str, MAX_PORT);
      }
    } else {
      zret.note(S_ERROR, R"(Address "{}" does not have the require port specifier.)", fqdn);
    }

  } else {
    zret.note(S_ERROR, R"(Malformed address "{}".)", fqdn);
  }
  return zret;
}

void
ThreadPool::wait_for_work(ThreadInfo *thread_info)
{
  // ready to roll, add to the pool.
  {
    std::unique_lock<std::mutex> lock(_threadPoolMutex);
    _threadPool.push_back(thread_info);
    _threadPoolCvar.notify_all();
  }

  // wait for a notification there's a session to process.
  {
    std::unique_lock<std::mutex> lock(thread_info->_mutex);
    while (!thread_info->data_ready()) {
      thread_info->_cvar.wait_for(lock, 100ms);
    }
  }
}

ThreadInfo *
ThreadPool::get_worker()
{
  ThreadInfo *thread_info = nullptr;
  {
    std::unique_lock<std::mutex> lock(this->_threadPoolMutex);
    while (_threadPool.size() == 0) {
      if (_allThreads.size() >= max_threads) {
        // Just sleep until a thread comes back
        _threadPoolCvar.wait(lock);
      } else { // Make a new thread
        // This is circuitous, but we do this so that the thread can put a
        // pointer to it's @c std::thread in it's info. Note the circular
        // dependency: there's no object until after the constructor is called
        // but the constructor needs to be called to get the object. Sigh.
        std::thread *t = &_allThreads.emplace_back();
        *t = this->make_thread(t);
        _threadPoolCvar.wait(lock); // expect the new thread to enter
                                    // itself in the pool and signal.
      }
    }
    thread_info = _threadPool.front();
    _threadPool.pop_front();
  }
  return thread_info;
}

void
ThreadPool::join_threads()
{
  for (auto &thread : _allThreads) {
    thread.join();
  }
}

void
ThreadPool::set_max_threads(size_t new_max)
{
  max_threads = new_max;
}
