/** @file
 * Polls on sockets for sessions.
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

class Session;
class Notifier;

/** Polls on the various sockets and awakes the waiting sessions as the sockets
 * become ready.
 *
 * This dispatches poll results to SocketNotifier which, on a separate thread,
 * dispatches notifications to the waiting sessions.
 *
 * Thus socket polling happens like so:
 * 1. Many sessions request polling for their sockets via
 *    SocketPoller::request_poll(). These sessions wait on their condition variable
 *    for a poll result.
 * 2. SocketPoller calls poll(2) on the set of sockets.
 * 3. As poll(2) returns that sockets are available, SocketPoller dispatches the
 *    poll results to SocketNotifier.
 * 4. SocketNotifier awakes the waiting sessions with the poll results.
 */
class SocketPoller
{
public:
  /** Start the thread which will call poll(2) on the registered file descriptors.
   */
  static void start_polling_thread();

  /** Stop and join any threads related to polling on file descriptors. */
  static void stop_polling_thread();

  /** Request a polling event for the session.
   *
   * @param[in] session The session for which polling should be registered.
   * @param[in] events The input to poll(2) for the fd. POLLIN, POLLOUT, etc.
   */
  static void request_poll(std::weak_ptr<Session> session, short events);

  /** Remove the session as an entity to poll upon.
   *
   * @param[in] fd The file descriptor to remove from the list of fds to poll upon.
   */
  static void remove_poll_request(int fd);

  /** Remove the specified file descriptors from the list of fds to poll upon.
   *
   * This function is more efficient than calling deregister_session for each
   * session in the vector because it grabs the lock only once.
   *
   * @param[in] fds The list of file descriptors to remove from the list of fds
   * to poll upon.
   */
  static void remove_poll_requests(std::vector<int> const &fds);

private:
  /** The set of information requested for a call to poll(2). */
  class PollInfo
  {
  public:
    PollInfo(std::weak_ptr<Session> session, short events);
    std::weak_ptr<Session> session;
    short events = 0;
  };

private:
  SocketPoller() = default;

  // Delete all other constructors to preserve the singleton.
  SocketPoller(const SocketPoller &) = delete;
  SocketPoller &operator=(const SocketPoller &) = delete;
  SocketPoller(SocketPoller &&) = delete;
  SocketPoller &operator=(SocketPoller &&) = delete;

  /** This is the main logic for SocketPolling.
   *
   * This continuously polls on the registered file descriptors and dispatches
   * notification requests to SocketNotifier as socket events are ready.
   */
  void _start_polling();

private:
  /** The poller singleton. */
  static SocketPoller _socket_poller;

  /** The timeout to pass to ::poll. This is set very small so that polls for one
   * set of fds doesn't block for new ones that may come a bit later. */
  static constexpr std::chrono::milliseconds const _poll_timeout = std::chrono::milliseconds(1);

  /** A flag to tell the polling thread to stop polling. */
  static bool _stop_polling_flag;

  /** The thread in which socket polling will be performed. */
  static std::thread _poller_thread;

  /** The socket file descriptors for which to poll.
   *
   * This is a map from file descriptor to the session and desired events for
   * that session.
   */
  std::unordered_map<int, PollInfo> _polling_requests;
  std::mutex _polling_requests_mutex;

  /** Many producers, one consumer. @a register_session awakes the polling
   * consumer from the set of session threads. */
  std::condition_variable _polling_requests_cv;
};
