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
#include <unordered_set>

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

/** Help maintain the memory of the "struct pollfd" array for ::poll. */
class PollFdManager
{
public:
  /** Reserve space in our containers in the constructor. */
  PollFdManager()
  {
    // default_max_threads is a reasonable approximation since we don't have
    // access to the ThreadPool instance to call get_max_threads. If the user
    // configured more, future emplace_backs will expand the size for us as
    // needed.
    _poll_fds.reserve(ThreadPool::default_max_threads);
    _contained_fds.reserve(ThreadPool::default_max_threads);
  }

  /** Add fd to our set, if it isn't in there already.
   * @param[in] fd The file descriptor to add.
   * @param[in] events The events to poll for on the file descriptor.
   */
  void
  add_fd(int fd, short events)
  {
    auto spot = _contained_fds.find(fd);
    if (spot != _contained_fds.end() && spot->second == events) {
      return;
    }
    _contained_fds.emplace(fd, events);
    _poll_fds.push_back(pollfd{fd, events, 0});
  }

  /** Remove the set of file descriptors from the polling set.
   *@param[in] fds_to_erase The file descriptors to remove.
   */
  void
  remove_fds(std::vector<int> const &fds_to_erase)
  {
    for (auto const &fd_to_erase : fds_to_erase) {
      _contained_fds.erase(fd_to_erase);
    }
    _poll_fds.erase(
        std::remove_if(
            _poll_fds.begin(),
            _poll_fds.end(),
            [this](struct pollfd const &poll_fd) {
              return _contained_fds.find(poll_fd.fd) == _contained_fds.end();
            }),
        _poll_fds.end());
  }

  /** Used as a parameter to ::poll. */
  struct pollfd *
  data()
  {
    return _poll_fds.data();
  }

  /** Used as a parameter to ::poll. */
  size_t
  size() const
  {
    return _poll_fds.size();
  }

  std::vector<struct pollfd> const &
  get_poll_fds() const
  {
    return _poll_fds;
  }

private:
  /// Manage the memory to use for ::poll.
  std::vector<struct pollfd> _poll_fds;

  /// fd -> poll events value.
  std::unordered_map<int, short> _contained_fds;
};

void
SocketPoller::_start_polling()
{
  Errata errata;

  // Declare these out here so there memory isn't reallocated on each iteration.
  PollFdManager poll_fd_manager;
  std::vector<NotificationInfo> notification_infos;
  std::vector<int> fds_to_deregister;
  // default_max_threads is a reasonable approximation. If the user configured
  // more, future emplace_backs will expand the size for us as needed.
  while (!SocketPoller::_stop_polling_flag) {
    // Clear maintains capacity.
    notification_infos.clear();
    fds_to_deregister.clear();
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

      // We have poll requests to process. Now populate the array of pollfd
      // objects as input to ::poll.
      for (auto const &[fd, polling_info] : _polling_requests) {
        poll_fd_manager.add_fd(fd, polling_info.events);
      }
    } // Unlock the _polling_requests_mutex.

    auto const poll_result =
        ::poll(poll_fd_manager.data(), poll_fd_manager.size(), SocketPoller::_poll_timeout.count());
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
    {
      std::lock_guard<std::mutex> lock(_polling_requests_mutex);
      for (auto const &poll_fd : poll_fd_manager.get_poll_fds()) {
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
    poll_fd_manager.remove_fds(fds_to_deregister);
    SocketNotifier::notify_sessions(notification_infos);
  }
}
