/** @file
 * Unit tests for HttpReplay.h.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "catch.hpp"
#include "core/https.h"

#include <cerrno>
#include <unistd.h>

TEST_CASE("ALPN string formatting", "[alpn]")
{
  SECTION("empty alpn")
  {
    const unsigned char no_protos[] = {0};
    CHECK(std::string("") == get_printable_alpn_string({(char *)no_protos, sizeof(no_protos)}));
  }
  SECTION("Single protocol")
  {
    const unsigned char one_protos[] = {2, 'h', '2'};
    CHECK(std::string("h2") == get_printable_alpn_string({(char *)one_protos, sizeof(one_protos)}));
  }
  SECTION("Two protocols")
  {
    const unsigned char two_protos[] = {2, 'h', '2', 7, 'h', 't', 't', 'p', '1', '.', '1'};
    CHECK(
        std::string("h2,http1.1") ==
        get_printable_alpn_string({(char *)two_protos, sizeof(two_protos)}));
  }
}

TEST_CASE("TLS close reasons are tracked", "[tls]")
{
  SECTION("SSL zero return is treated as a clean peer close")
  {
    int fd_pair[2];
    REQUIRE(::pipe(fd_pair) == 0);

    TLSSession session;
    REQUIRE(session.set_fd(fd_pair[0]).is_ok());
    ::close(fd_pair[1]);

    auto const poll_result =
        session.poll_for_data_on_ssl_socket(std::chrono::milliseconds{1}, SSL_ERROR_ZERO_RETURN);

    CHECK(poll_result.result() < 0);
    CHECK(session.is_closed());
    CHECK(session.is_closed_cleanly_by_peer());
    CHECK(session.get_close_reason() == Session::CloseReason::PEER_CLOSE);

    int reconnect_fd_pair[2];
    REQUIRE(::pipe(reconnect_fd_pair) == 0);
    REQUIRE(session.set_fd(reconnect_fd_pair[0]).is_ok());
    ::close(reconnect_fd_pair[1]);

    CHECK(session.get_close_reason() == Session::CloseReason::UNSPECIFIED);
    session.close();
  }

  SECTION("SSL protocol errors stay fatal")
  {
    int fd_pair[2];
    REQUIRE(::pipe(fd_pair) == 0);

    TLSSession session;
    REQUIRE(session.set_fd(fd_pair[0]).is_ok());
    ::close(fd_pair[1]);

    auto const poll_result =
        session.poll_for_data_on_ssl_socket(std::chrono::milliseconds{1}, SSL_ERROR_SSL);

    CHECK(poll_result.result() < 0);
    CHECK(session.is_closed());
    CHECK_FALSE(session.is_closed_cleanly_by_peer());
    CHECK(session.get_close_reason() == Session::CloseReason::PEER_ERROR);
  }

  SECTION("EOF-style SSL_ERROR_SYSCALL is treated as a clean peer close")
  {
    ERR_clear_error();
    errno = 0;
    CHECK(
        TLSSession::classify_ssl_close_reason(SSL_ERROR_SYSCALL) ==
        Session::CloseReason::PEER_CLOSE);
  }

  SECTION("SSL_ERROR_SYSCALL with errno set is treated as an error")
  {
    ERR_clear_error();
    errno = EIO;
    CHECK(
        TLSSession::classify_ssl_close_reason(SSL_ERROR_SYSCALL) ==
        Session::CloseReason::PEER_ERROR);
    errno = 0;
  }
}
