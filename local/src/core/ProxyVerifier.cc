/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/ProxyVerifier.h"
#include "core/verification.h"

#include <algorithm>
#include <cassert>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

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

swoc::Rv<int>
block_sigpipe()
{
  swoc::Rv<int> zret = 0;
  sigset_t set;
  if (sigemptyset(&set)) {
    zret = -1;
    zret.error(R"(Could not empty the signal set: {})", swoc::bwf::Errno{});
  } else if (sigaddset(&set, SIGPIPE)) {
    zret = -1;
    zret.error(R"(Could not add SIGPIPE to the signal set: {})", swoc::bwf::Errno{});
  } else if (pthread_sigmask(SIG_BLOCK, &set, nullptr)) {
    zret = -1;
    zret.error(R"(Could not block SIGPIPE: {})", swoc::bwf::Errno{});
  }
  return zret;
}

swoc::Errata
configure_logging(const std::string_view verbose_argument)
{
  swoc::Errata errata;
  auto severity_cutoff = swoc::Severity::INFO;
  if (strcasecmp(verbose_argument, "error") == 0) {
    severity_cutoff = swoc::Severity::ERROR;
  } else if (strcasecmp(verbose_argument, "warn") == 0) {
    severity_cutoff = swoc::Severity::WARN;
  } else if (strcasecmp(verbose_argument, "info") == 0) {
    severity_cutoff = swoc::Severity::INFO;
  } else if (strcasecmp(verbose_argument, "diag") == 0) {
    severity_cutoff = swoc::Severity::DIAG;
  } else {
    errata.error("Unrecognized verbosity parameter: {}", verbose_argument);
    return errata;
  }
  errata.diag("Configuring logging at level {}", severity_cutoff);

  static std::mutex logging_mutex;

  swoc::Errata::register_sink([severity_cutoff](Errata const &errata) {
    if (errata.severity() < severity_cutoff) {
      return;
    }
    std::string_view lead;
    for (auto const &annotation : errata) {
      if (annotation.severity() < severity_cutoff) {
        continue;
      }
      {
        std::lock_guard<std::mutex> lock(logging_mutex);
        std::cout << lead << " [" << static_cast<int>(annotation.severity())
                  << "]: " << annotation.text() << std::endl;
      }
      if (lead.size() == 0) {
        lead = "  "_sv;
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
      errata.error(R"("{}" is not a valid IP address.)", name);
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
      errata.error(R"("{}" is not a valid IP address.)", name);
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
        port = htons(n);
        if (addr.load(host_str)) {
          zret.result().assign(addr, port);
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
            zret.result().assign(addrs->ai_addr);
            zret.result().port() = port;
            freeaddrinfo(addrs);
          } else {
            zret.error(R"(Failed to resolve "{}": {}.)", host_str, swoc::bwf::Errno(result));
          }
        }
      } else {
        zret.error(R"(Port value {} out of range [ 1 .. {} ].)", port_str, MAX_PORT);
      }
    } else {
      zret.error(R"(Address "{}" does not have the require port specifier.)", fqdn);
    }

  } else {
    zret.error(R"(Malformed address "{}".)", fqdn);
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
