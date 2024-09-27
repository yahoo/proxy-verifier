/** @file
 * Notifies waiting sessions that their poll has completed.
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

class Session;

/** The information needed to notify a session that its poll is done. */
struct NotificationInfo
{
  NotificationInfo(std::weak_ptr<Session> session, int revent);

  /** The session awaiting a poll result. */
  std::weak_ptr<Session> session;

  /** The poll output variable for this session's poll. */
  int revents = 0;
};

/** Notifies waiting sessions that their sockets are ready.
 *
 * Note that this class used as a helper class for SocketPoller. No other
 * entities should require using this class.
 */
class SocketNotifier
{
public:
  /** Notify sessions that their poll events are done.
   *
   * @param[in] notification_infos The list of sessions and their poll events.
   */
  static void notify_sessions(std::vector<NotificationInfo> const &notification_infos);

  /** No longer notify the indicated session.
   * @param[in] fd The file descriptor of the session to no longer notify.
   */
  static void drop_session_notification(int fd);

  /** Start the thread to notify sessions. */
  static void start_notifier_thread();

  /** Stop the thread for notification. */
  static void stop_notifier_thread();

private:
  SocketNotifier() = default;

  // Delete all other constructors to preserve the singleton.
  SocketNotifier(const SocketNotifier &) = delete;
  SocketNotifier &operator=(const SocketNotifier &) = delete;
  SocketNotifier(SocketNotifier &&) = delete;
  SocketNotifier &operator=(SocketNotifier &&) = delete;

  /** This is the notification loop run continuously in a thread. It dispatches
   * notification results from the SocketPoller.
   */
  void _start_notifying();

private:
  /** The notifier singleton. */
  static SocketNotifier _socket_notifier;
  static bool _stop_notifier_flag;

  /** The outstanding callbacks that still need to be dispatched. */
  std::unordered_map<int, NotificationInfo> _notification_infos;
  std::mutex _notification_infos_mutex;

  /** The Poller is our producer which wakes up the thread via @a notify_sessions. */
  std::condition_variable _notification_infos_cv;

  static std::thread _notifier_thread;
};
