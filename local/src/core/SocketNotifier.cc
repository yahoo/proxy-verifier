/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/SocketNotifier.h"
#include "core/http.h"

#include <mutex>
#include <thread>

// Static instantiations.
SocketNotifier SocketNotifier::_socket_notifier; // Our singleton.
std::thread SocketNotifier::_notifier_thread;
bool SocketNotifier::_stop_notifier_flag = false;

NotificationInfo::NotificationInfo(std::weak_ptr<Session> session, int revent)
  : session(session)
  , revents(revent)
{
}

void
SocketNotifier::notify_sessions(std::vector<NotificationInfo> const &notification_infos)
{
  {
    std::lock_guard<std::mutex> lock(_socket_notifier._notification_infos_mutex);
    for (auto const &notification_info : notification_infos) {
      if (auto session = notification_info.session.lock(); session) {
        _socket_notifier._notification_infos.emplace(session->get_fd(), notification_info);
      }
    }
  }
  _socket_notifier._notification_infos_cv.notify_one();
}

void
SocketNotifier::drop_session_notification(int fd)
{
  std::lock_guard<std::mutex> lock(_socket_notifier._notification_infos_mutex);
  _socket_notifier._notification_infos.erase(fd);
}

void
SocketNotifier::start_notifier_thread()
{
  _stop_notifier_flag = false;
  _notifier_thread = std::thread([]() { SocketNotifier::_socket_notifier._start_notifying(); });
}

void
SocketNotifier::stop_notifier_thread()
{
  _stop_notifier_flag = true;
  _socket_notifier._notification_infos_cv.notify_one();
  _notifier_thread.join();
}

void
SocketNotifier::_start_notifying()
{
  while (!SocketNotifier::_stop_notifier_flag) {
    std::unique_lock<std::mutex> lock(_notification_infos_mutex);
    _notification_infos_cv.wait(lock, [this]() {
      return !_notification_infos.empty() || SocketNotifier::_stop_notifier_flag;
    });

    if (SocketNotifier::_stop_notifier_flag) {
      break;
    }

    for (auto &[fd, notification_info] : _notification_infos) {
      auto &[weak_session, revents] = notification_info;
      if (auto session = weak_session.lock(); session) {
        session->handle_poll_return(revents);
      }
    }
    _notification_infos.clear();
  }
}
