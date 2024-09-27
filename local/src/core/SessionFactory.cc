/** @file
 * Implement a factory to create Session objects.
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include <core/http.h>
#include <core/http2.h>
#include <core/https.h>
#include <core/http3.h>

#include <memory>

std::shared_ptr<Session>
Session::create_session(SessionType type)
{
  switch (type) {
  case SessionType::TCP:
    return std::make_shared<Session>(PrivateKey{});
  case SessionType::TLS:
    return std::static_pointer_cast<Session>(std::make_shared<TLSSession>(PrivateKey{}));
  case SessionType::HTTP2:
    return std::static_pointer_cast<Session>(std::make_shared<H2Session>(PrivateKey{}));
  case SessionType::QUIC:
    return std::static_pointer_cast<Session>(std::make_shared<H3Session>(PrivateKey{}));
  }
  return nullptr; // Not reached.
}

std::shared_ptr<Session>
Session::create_tcp_session()
{
  return std::make_shared<Session>(PrivateKey{});
}

std::shared_ptr<Session>
Session::create_tls_session(std::string_view client_sni, int verify_mode)
{
  return std::static_pointer_cast<Session>(
      std::make_shared<TLSSession>(PrivateKey{}, client_sni, verify_mode));
}

std::shared_ptr<Session>
Session::create_h2_session(std::string_view client_sni, int verify_mode, bool close_on_goaway)
{
  return std::static_pointer_cast<Session>(
      std::make_shared<H2Session>(PrivateKey{}, client_sni, verify_mode, close_on_goaway));
}

std::shared_ptr<Session>
Session::create_h3_session(std::string_view client_sni, int verify_mode)
{
  return std::static_pointer_cast<Session>(
      std::make_shared<H3Session>(PrivateKey{}, client_sni, verify_mode));
}
