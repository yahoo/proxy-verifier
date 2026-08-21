/** @file
 * Unit tests for the socket I/O backend.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"

#include "core/socket_io.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace std::literals;

TEST_CASE("Socket I/O modes are parsed", "[socket_io]")
{
  CHECK(parse_socket_io_mode("auto").result() == SocketIoMode::AUTO);
  CHECK(parse_socket_io_mode("off").result() == SocketIoMode::OFF);
  CHECK(parse_socket_io_mode("required").result() == SocketIoMode::REQUIRED);
  CHECK_FALSE(parse_socket_io_mode("invalid").is_ok());
}

TEST_CASE("Socket I/O reports the selected backend", "[socket_io]")
{
  auto const require_io_uring = std::getenv("PV_TEST_REQUIRE_IO_URING") != nullptr;
  auto const mode = require_io_uring ? SocketIoMode::REQUIRED : SocketIoMode::AUTO;
  auto &&[backend, errata] = configure_socket_io(mode);
  REQUIRE(errata.is_ok());
  auto const name = socket_io_backend_name(backend);
  if (require_io_uring) {
    REQUIRE(backend == SocketIoBackend::IO_URING);
    CHECK(name == "io_uring");
  } else {
    CHECK((name == "poll" || name == "io_uring"));
  }
}

TEST_CASE("Socket I/O waits for readiness and timeout", "[socket_io]")
{
  int sockets[2] = {-1, -1};
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

  CHECK(poll_for_socket_io(sockets[0], 0ms, POLLIN) == 0);
  for (int attempt = 0; attempt < 8; ++attempt) {
    CHECK(poll_for_socket_io(sockets[0], 1ms, POLLIN) == 0);
  }

  char const content = 'x';
  REQUIRE(::write(sockets[1], &content, sizeof(content)) == sizeof(content));
  CHECK(poll_for_socket_io(sockets[0], 0ms, POLLIN) > 0);
  CHECK(poll_for_socket_io(sockets[0], 100ms, POLLIN) > 0);
  CHECK(poll_for_socket_io(sockets[0], 100ms, POLLOUT) > 0);

  ::close(sockets[0]);
  ::close(sockets[1]);
}

TEST_CASE("Socket I/O handles concurrent readiness waits", "[socket_io]")
{
  static constexpr size_t SOCKET_COUNT = 32;
  std::array<std::array<int, 2>, SOCKET_COUNT> sockets;
  for (auto &pair : sockets) {
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, pair.data()) == 0);
  }

  std::array<int, SOCKET_COUNT> results{};
  std::vector<std::thread> waiters;
  waiters.reserve(SOCKET_COUNT);
  for (size_t index = 0; index < SOCKET_COUNT; ++index) {
    waiters.emplace_back(
        [&, index] { results[index] = poll_for_socket_io(sockets[index][0], 500ms, POLLIN); });
  }

  char const content = 'x';
  for (auto const &pair : sockets) {
    CHECK(::write(pair[1], &content, sizeof(content)) == sizeof(content));
  }
  for (auto &waiter : waiters) {
    waiter.join();
  }

  for (size_t index = 0; index < SOCKET_COUNT; ++index) {
    CHECK(results[index] > 0);
    ::close(sockets[index][0]);
    ::close(sockets[index][1]);
  }
}
