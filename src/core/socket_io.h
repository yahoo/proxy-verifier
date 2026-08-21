/** @file
 * Socket readiness backend selection and polling.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <chrono>

#include "swoc/Errata.h"
#include "swoc/TextView.h"

/** The requested socket I/O backend policy. */
enum class SocketIoMode {
  AUTO,     ///< Use io_uring when it is available, otherwise use poll.
  OFF,      ///< Always use poll.
  REQUIRED, ///< Require io_uring initialization to succeed.
};

/** The socket I/O backend selected for this process. */
enum class SocketIoBackend {
  POLL,    ///< The portable poll(2) backend.
  IO_URING ///< The Linux io_uring backend.
};

/** Parse a socket I/O backend policy.
 *
 * @param[in] value The policy name: auto, off, or required.
 * @return The parsed policy, or an error for an unsupported value.
 */
swoc::Rv<SocketIoMode> parse_socket_io_mode(swoc::TextView value);

/** Parse and configure the process-wide socket I/O backend.
 *
 * @param[in] value The requested backend policy name.
 * @return The selected backend, or an error for an invalid or unavailable
 * configuration.
 */
swoc::Rv<SocketIoBackend> configure_socket_io(swoc::TextView value);

/** Configure the process-wide socket I/O backend.
 *
 * This must be called before the first call to poll_for_socket_io(). Repeated
 * calls return the backend selected by the first call.
 *
 * @param[in] mode The requested backend policy.
 * @return The selected backend, or an error if io_uring was required but was
 * unavailable.
 */
swoc::Rv<SocketIoBackend> configure_socket_io(SocketIoMode mode);

/** Get a printable name for a socket I/O backend.
 *
 * @param[in] backend The backend to describe.
 * @return The backend name.
 */
swoc::TextView socket_io_backend_name(SocketIoBackend backend);

/** Wait for events on a socket using the configured backend.
 *
 * io_uring is used when it was compiled in and can be initialized by the
 * running kernel. Otherwise this transparently calls poll(2).
 *
 * @param[in] fd The socket file descriptor.
 * @param[in] timeout The maximum time to wait.
 * @param[in] events The poll event mask to wait for.
 * @return 0 on timeout, -1 on failure, or a positive value when ready.
 */
int poll_for_socket_io(int fd, std::chrono::milliseconds timeout, short events);
