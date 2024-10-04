/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/SocketPoller.h"
#include "core/http.h"
#include "core/ProxyVerifier.h"
#include "core/SocketNotifier.h"

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/Errata.h"

#include <chrono>
#include <mutex>
#include <thread>

using swoc::Errata;

// Static instantiations.
SocketPoller SocketPoller::_socket_poller; // Our singleton.
std::thread SocketPoller::_poller_thread;
bool SocketPoller::_stop_polling_flag = false;

SocketPoller::PollInfo::PollInfo(std::weak_ptr<Session> session, short events)
  : session(session)
  , events(events)
{
}

void
SocketPoller::request_poll(std::weak_ptr<Session> session, short events)
{
  {
    std::lock_guard<std::mutex> lock(_socket_poller._polling_requests_mutex);
    if (auto locked_session = session.lock(); locked_session) {
      _socket_poller._polling_requests.emplace(locked_session->get_fd(), PollInfo{session, events});
    }
  }
  _socket_poller._polling_requests_cv.notify_one();
}

void
SocketPoller::remove_poll_request(int fd)
{
  {
    std::lock_guard<std::mutex> lock(_socket_poller._polling_requests_mutex);
    _socket_poller._polling_requests.erase(fd);
  } // Unlock the _polling_requests_mutex.
  SocketNotifier::drop_session_notification(fd);
}

void
SocketPoller::remove_poll_requests(std::vector<int> const &fds)
{
  std::lock_guard<std::mutex> lock(_socket_poller._polling_requests_mutex);
  for (auto const &fd : fds) {
    _socket_poller._polling_requests.erase(fd);
  }
}

void
SocketPoller::start_polling_thread()
{
  SocketPoller::_stop_polling_flag = false;
  SocketNotifier::start_notifier_thread();
  _poller_thread = std::thread([]() { SocketPoller::_socket_poller._start_polling(); });
}

void
SocketPoller::stop_polling_thread()
{
  SocketNotifier::stop_notifier_thread();
  SocketPoller::_stop_polling_flag = true;
  _socket_poller._polling_requests_cv.notify_one();
  SocketPoller::_poller_thread.join();
}

void
SocketPoller::_start_polling()
{
  Errata errata;
  while (!SocketPoller::_stop_polling_flag) {
    // Populate the array of pollfd objects as input to ::poll.
    std::vector<struct pollfd> poll_fds;
    {
      // Wait for the request_poll producer to add sessions to poll upon.
      std::unique_lock<std::mutex> lock(_polling_requests_mutex);
      _polling_requests_cv.wait(lock, [this]() {
        return !_polling_requests.empty() || SocketPoller::_stop_polling_flag;
      });

      // Either we (1) received poll requests, or (2) we have been asked to stop
      // polling. Handle both cases.
      if (SocketPoller::_stop_polling_flag) {
        break;
      }

      // We have poll requests to process.

      poll_fds.reserve(_polling_requests.size());
      for (auto const &[fd, polling_info] : _polling_requests) {
        poll_fds.push_back({fd, polling_info.events, 0});
      }
    } // Unlock the _polling_requests_mutex.

    auto const poll_result =
        ::poll(poll_fds.data(), poll_fds.size(), SocketPoller::_poll_timeout.count());
    if (poll_result == 0) {
      // Timeout. Simply loop backaround and poll again. Maybe other fd's have
      // been registered.
      continue;
    } else if (poll_result < 0) {
      // Error condition.
      if (errno == EINTR) {
        continue;
      }
      errata.note(S_ERROR, "poll failed: {}", swoc::bwf::Errno{});
      return;
    }

    // Poll succeeded. There are events to process.

    // Call back each session that requested a poll.
    std::vector<NotificationInfo> notification_infos;
    std::vector<int> fds_to_deregister;
    {
      std::lock_guard<std::mutex> lock(_polling_requests_mutex);
      for (auto const &poll_fd : poll_fds) {
        if (poll_fd.revents == 0) {
          // This fd did not have an event. Move on.
          continue;
        }
        auto sock_fd = poll_fd.fd;
        // Make sure that, in the meantime, the session didn't time out and
        // move on and deregister itself.
        auto spot = _polling_requests.find(sock_fd);
        if (spot == _polling_requests.end()) {
          continue;
        }
        auto session = spot->second.session;
        notification_infos.emplace_back(session, poll_fd.revents);
        fds_to_deregister.push_back(sock_fd);
      }
    } // Unlock the _polling_requests_mutex.
    SocketPoller::remove_poll_requests(fds_to_deregister);
    SocketNotifier::notify_sessions(notification_infos);
  }
}
