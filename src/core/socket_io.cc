/** @file
 * Socket readiness backend selection and polling.
 *
 * Copyright 2026, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/socket_io.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <poll.h>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/ProxyVerifier.h"

#if defined(PV_HAVE_LIBURING)
#include <liburing.h>
#include <sys/eventfd.h>
#include <unistd.h>
#endif

using swoc::TextView;
using namespace swoc::literals;
namespace chrono = std::chrono;

namespace
{
class SocketIoService
{
public:
  explicit SocketIoService(SocketIoMode mode);
  ~SocketIoService();

  SocketIoService(SocketIoService const &) = delete;
  SocketIoService &operator=(SocketIoService const &) = delete;

  SocketIoBackend backend() const;
  bool fallback_allowed() const;
  std::string const &failure_reason() const;
  int poll(int fd, chrono::milliseconds timeout, short events);

private:
#if defined(PV_HAVE_LIBURING)
  using Clock = chrono::steady_clock;
  using TimePoint = Clock::time_point;

  struct PollOperation;
  using DeadlineMap = std::multimap<TimePoint, PollOperation *>;

  struct PollOperation
  {
  public:
    PollOperation(int socket_fd, short poll_events, TimePoint operation_deadline);

    int wait();
    void complete(int operation_result, int operation_error);

  public:
    int const fd;
    short const events;
    TimePoint const deadline;
    bool timeout_requested = false;
    bool shutdown_requested = false;
    DeadlineMap::iterator deadline_entry;
    bool deadline_registered = false;

  private:
    std::mutex m_mutex;
    std::condition_variable m_cv;
    int m_result = -1;
    int m_error = 0;
    bool m_complete = false;
  };

  static constexpr unsigned SUBMISSION_QUEUE_SIZE = 256;
  static constexpr unsigned COMPLETION_QUEUE_SIZE = 8'192;
  static constexpr std::uint64_t WAKE_TOKEN = 1;
  static constexpr std::uint64_t IGNORE_TOKEN = 2;

  bool initialize();
  void run();
  void notify();
  void drain_notification();
  void process_commands();
  void process_completion(io_uring_cqe const &completion);
  unsigned reap_completions();
  void drain_completions();
  void expire_deadlines(TimePoint now);
  bool request_cancellation(std::shared_ptr<PollOperation> const &operation);
  void request_shutdown();
  void fail_service(int error);
  bool submit_pending();
  io_uring_sqe *get_submission();
  chrono::nanoseconds time_until_next_deadline(TimePoint now);

  io_uring m_ring{};
  int m_event_fd = -1;
  std::thread m_completion_thread;
  std::mutex m_command_mutex;
  std::deque<std::shared_ptr<PollOperation>> m_commands;
  std::deque<io_uring_cqe> m_deferred_completions;
  std::unordered_map<PollOperation *, std::shared_ptr<PollOperation>> m_pending;
  DeadlineMap m_deadlines;
  bool m_accepting_requests = false;
  bool m_stop_requested = false;
  bool m_stop_after_pending = false;
  bool m_ring_initialized = false;
#endif

  std::atomic<bool> m_available = false;
  std::string m_failure_reason;
  bool const m_fallback_allowed;
};

SocketIoService &
socket_io_service(SocketIoMode mode = SocketIoMode::AUTO)
{
  static SocketIoService service{mode};
  return service;
}

int
poll_with_system_call(int fd, chrono::milliseconds timeout, short events)
{
  auto const timeout_ms = std::max<chrono::milliseconds::rep>(timeout.count(), 0);
  pollfd descriptor = {.fd = fd, .events = events, .revents = 0};
  return ::poll(&descriptor, 1, timeout_ms);
}
} // namespace

#if defined(PV_HAVE_LIBURING)
SocketIoService::PollOperation::PollOperation(
    int socket_fd,
    short poll_events,
    TimePoint operation_deadline)
  : fd(socket_fd)
  , events(poll_events)
  , deadline(operation_deadline)
{
}

int
SocketIoService::PollOperation::wait()
{
  std::unique_lock<std::mutex> lock{m_mutex};
  m_cv.wait(lock, [this] { return m_complete; });
  if (m_result < 0) {
    errno = m_error;
  }
  return m_result;
}

void
SocketIoService::PollOperation::complete(int operation_result, int operation_error)
{
  {
    std::lock_guard<std::mutex> lock{m_mutex};
    if (m_complete) {
      return;
    }
    m_result = operation_result;
    m_error = operation_error;
    m_complete = true;
  }
  m_cv.notify_one();
}

#endif

SocketIoService::SocketIoService(SocketIoMode mode)
  : m_fallback_allowed(mode != SocketIoMode::REQUIRED)
{
#if defined(PV_HAVE_LIBURING)
  if (mode != SocketIoMode::OFF) {
    initialize();
  } else {
    m_failure_reason = "io_uring was disabled";
  }
#else
  static_cast<void>(mode);
  m_failure_reason = "this build does not include liburing support";
#endif
}

SocketIoService::~SocketIoService()
{
#if defined(PV_HAVE_LIBURING)
  if (m_completion_thread.joinable()) {
    if (m_available) {
      {
        std::lock_guard<std::mutex> lock{m_command_mutex};
        m_accepting_requests = false;
        m_stop_requested = true;
      }
      notify();
    }
    m_completion_thread.join();
  }
  if (m_ring_initialized) {
    if (m_event_fd >= 0) {
      ::close(m_event_fd);
    }
    io_uring_queue_exit(&m_ring);
  }
#endif
}

SocketIoBackend
SocketIoService::backend() const
{
  return m_available ? SocketIoBackend::IO_URING : SocketIoBackend::POLL;
}

bool
SocketIoService::fallback_allowed() const
{
  return m_fallback_allowed;
}

std::string const &
SocketIoService::failure_reason() const
{
  return m_failure_reason;
}

int
SocketIoService::poll(int fd, chrono::milliseconds timeout, short events)
{
#if defined(PV_HAVE_LIBURING)
  auto operation = std::make_shared<PollOperation>(fd, events, Clock::now() + timeout);
  {
    std::lock_guard<std::mutex> lock{m_command_mutex};
    if (!m_accepting_requests) {
      errno = ECANCELED;
      return -1;
    }
    m_commands.push_back(operation);
  }
  notify();
  return operation->wait();
#else
  static_cast<void>(fd);
  static_cast<void>(timeout);
  static_cast<void>(events);
  errno = ENOSYS;
  return -1;
#endif
}

#if defined(PV_HAVE_LIBURING)
bool
SocketIoService::initialize()
{
  io_uring_params parameters{};
  parameters.flags = IORING_SETUP_CQSIZE;
  parameters.cq_entries = COMPLETION_QUEUE_SIZE;
  auto const setup_result = io_uring_queue_init_params(SUBMISSION_QUEUE_SIZE, &m_ring, &parameters);
  if (setup_result < 0) {
    m_failure_reason = std::string{"io_uring_queue_init failed: "} + strerror(-setup_result);
    return false;
  }
  m_ring_initialized = true;

  if ((parameters.features & IORING_FEAT_NODROP) == 0) {
    m_failure_reason = "the kernel does not support lossless io_uring completions";
    io_uring_queue_exit(&m_ring);
    m_ring_initialized = false;
    return false;
  }

  auto *probe = io_uring_get_probe_ring(&m_ring);
  if (probe == nullptr || !io_uring_opcode_supported(probe, IORING_OP_POLL_ADD) ||
      !io_uring_opcode_supported(probe, IORING_OP_ASYNC_CANCEL))
  {
    m_failure_reason = "the kernel does not support required io_uring operations";
    if (probe != nullptr) {
      io_uring_free_probe(probe);
    }
    io_uring_queue_exit(&m_ring);
    m_ring_initialized = false;
    return false;
  }
  io_uring_free_probe(probe);

  m_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  if (m_event_fd < 0) {
    m_failure_reason = std::string{"eventfd initialization failed: "} + strerror(errno);
    io_uring_queue_exit(&m_ring);
    m_ring_initialized = false;
    return false;
  }

  auto *submission = get_submission();
  if (submission == nullptr) {
    m_failure_reason = "could not allocate the initial io_uring submission";
    ::close(m_event_fd);
    m_event_fd = -1;
    io_uring_queue_exit(&m_ring);
    m_ring_initialized = false;
    return false;
  }
  io_uring_prep_poll_add(submission, m_event_fd, POLLIN);
  submission->user_data = WAKE_TOKEN;
  if (!submit_pending()) {
    m_failure_reason = std::string{"initial io_uring submission failed: "} + strerror(errno);
    ::close(m_event_fd);
    m_event_fd = -1;
    io_uring_queue_exit(&m_ring);
    m_ring_initialized = false;
    return false;
  }

  m_accepting_requests = true;
  m_available = true;
  try {
    m_completion_thread = std::thread{&SocketIoService::run, this};
  } catch (std::system_error const &error) {
    m_accepting_requests = false;
    m_available = false;
    m_failure_reason =
        std::string{"io_uring completion thread initialization failed: "} + error.what();
    ::close(m_event_fd);
    m_event_fd = -1;
    io_uring_queue_exit(&m_ring);
    m_ring_initialized = false;
    return false;
  }
  return true;
}

void
SocketIoService::notify()
{
  std::uint64_t increment = 1;
  while (::write(m_event_fd, &increment, sizeof(increment)) < 0) {
    if (errno == EINTR) {
      continue;
    }
    // EAGAIN means a previous notification is still pending.
    break;
  }
}

void
SocketIoService::drain_notification()
{
  std::uint64_t value = 0;
  while (::read(m_event_fd, &value, sizeof(value)) < 0 && errno == EINTR) {
  }
}

io_uring_sqe *
SocketIoService::get_submission()
{
  auto *submission = io_uring_get_sqe(&m_ring);
  if (submission == nullptr && submit_pending()) {
    submission = io_uring_get_sqe(&m_ring);
    if (submission == nullptr) {
      errno = EAGAIN;
    }
  }
  return submission;
}

bool
SocketIoService::submit_pending()
{
  while (io_uring_sq_ready(&m_ring) > 0) {
    auto const result = io_uring_submit(&m_ring);
    if (result > 0) {
      continue;
    }
    if (result == -EINTR) {
      continue;
    }
    if (result == -EBUSY) {
      // IORING_FEAT_NODROP reports CQ overflow through EBUSY. Reaping the
      // available completions makes room for the kernel to flush overflowed
      // entries on the next submission attempt. Defer processing so callers
      // cannot be re-entered while they hold references into service state.
      if (reap_completions() > 0) {
        continue;
      }
    }
    errno = result < 0 ? -result : EIO;
    return false;
  }
  return true;
}

void
SocketIoService::process_commands()
{
  drain_notification();

  std::deque<std::shared_ptr<PollOperation>> commands;
  bool stop_requested = false;
  {
    std::lock_guard<std::mutex> lock{m_command_mutex};
    commands.swap(m_commands);
    stop_requested = m_stop_requested;
  }

  if (stop_requested) {
    for (auto const &operation : commands) {
      operation->complete(-1, ECANCELED);
    }
    request_shutdown();
    return;
  }

  for (auto const &operation : commands) {
    auto *submission = get_submission();
    if (submission == nullptr) {
      operation->complete(-1, errno);
      continue;
    }
    m_pending.emplace(operation.get(), operation);
    operation->deadline_entry = m_deadlines.emplace(operation->deadline, operation.get());
    operation->deadline_registered = true;
    io_uring_prep_poll_add(submission, operation->fd, operation->events);
    submission->user_data = reinterpret_cast<std::uint64_t>(operation.get());
  }

  auto *submission = get_submission();
  if (submission == nullptr) {
    fail_service(errno);
    return;
  }
  io_uring_prep_poll_add(submission, m_event_fd, POLLIN);
  submission->user_data = WAKE_TOKEN;
  if (!submit_pending()) {
    fail_service(errno);
  }
}

bool
SocketIoService::request_cancellation(std::shared_ptr<PollOperation> const &operation)
{
  auto *submission = get_submission();
  if (submission == nullptr) {
    return false;
  }
  io_uring_prep_cancel(submission, operation.get(), 0);
  submission->user_data = IGNORE_TOKEN;
  return true;
}

void
SocketIoService::request_shutdown()
{
  m_stop_after_pending = true;
  std::vector<std::shared_ptr<PollOperation>> pending_operations;
  pending_operations.reserve(m_pending.size());
  for (auto const &[operation_pointer, operation] : m_pending) {
    static_cast<void>(operation_pointer);
    pending_operations.push_back(operation);
  }
  for (auto const &operation : pending_operations) {
    operation->shutdown_requested = true;
    if (!request_cancellation(operation)) {
      fail_service(errno);
      return;
    }
  }
  if (m_pending.empty()) {
    return;
  }
  if (!submit_pending()) {
    fail_service(errno);
  }
}

void
SocketIoService::process_completion(io_uring_cqe const &completion)
{
  if (completion.user_data == WAKE_TOKEN) {
    process_commands();
    return;
  }
  if (completion.user_data == IGNORE_TOKEN) {
    return;
  }

  auto *operation_pointer = reinterpret_cast<PollOperation *>(completion.user_data);
  auto spot = m_pending.find(operation_pointer);
  if (spot == m_pending.end()) {
    return;
  }

  auto operation = std::move(spot->second);
  m_pending.erase(spot);
  if (operation->deadline_registered) {
    m_deadlines.erase(operation->deadline_entry);
    operation->deadline_registered = false;
  }
  if (operation->shutdown_requested) {
    operation->complete(-1, ECANCELED);
  } else if (completion.res > 0) {
    operation->complete(1, 0);
  } else if (operation->timeout_requested) {
    operation->complete(0, 0);
  } else if (completion.res >= 0) {
    operation->complete(completion.res == 0 ? 0 : 1, 0);
  } else {
    operation->complete(-1, -completion.res);
  }
}

unsigned
SocketIoService::reap_completions()
{
  unsigned completion_count = 0;
  io_uring_cqe *completion = nullptr;
  while (io_uring_peek_cqe(&m_ring, &completion) == 0) {
    m_deferred_completions.push_back(*completion);
    io_uring_cqe_seen(&m_ring, completion);
    ++completion_count;
  }
  return completion_count;
}

void
SocketIoService::drain_completions()
{
  reap_completions();
  // Completion processing can reap more CQEs into the back of this deque;
  // copying and popping the front before dispatch makes that safe.
  while (!m_deferred_completions.empty()) {
    auto const completed_entry = m_deferred_completions.front();
    m_deferred_completions.pop_front();
    process_completion(completed_entry);
  }
}

void
SocketIoService::expire_deadlines(TimePoint now)
{
  while (!m_deadlines.empty()) {
    auto const entry = m_deadlines.begin();
    if (entry->first > now) {
      break;
    }
    auto const operation_pointer = entry->second;
    auto const spot = m_pending.find(operation_pointer);
    if (spot == m_pending.end()) {
      m_deadlines.erase(entry);
      continue;
    }
    auto const operation = spot->second;
    m_deadlines.erase(entry);
    operation->deadline_registered = false;
    operation->timeout_requested = true;
    if (!request_cancellation(operation)) {
      fail_service(errno);
      return;
    }
  }
}

chrono::nanoseconds
SocketIoService::time_until_next_deadline(TimePoint now)
{
  if (!m_deadlines.empty()) {
    return std::max(
        chrono::duration_cast<chrono::nanoseconds>(m_deadlines.begin()->first - now),
        chrono::nanoseconds{1});
  }
  return chrono::nanoseconds::max();
}

void
SocketIoService::fail_service(int error)
{
  if (!m_available.load()) {
    return;
  }
  m_failure_reason = std::string{"io_uring runtime failure: "} + strerror(error);
  if (!m_available.exchange(false)) {
    return;
  }
  swoc::Errata errata;
  errata.note(
      S_ERROR,
      "The io_uring socket I/O backend was disabled after a runtime failure: {}. {}",
      strerror(error),
      m_fallback_allowed ? "Future waits will use poll(2)." : "poll(2) fallback is disabled.");
  std::deque<std::shared_ptr<PollOperation>> commands;
  {
    std::lock_guard<std::mutex> lock{m_command_mutex};
    m_accepting_requests = false;
    commands.swap(m_commands);
  }
  for (auto const &operation : commands) {
    operation->complete(-1, error);
  }
  for (auto const &[operation_pointer, operation] : m_pending) {
    static_cast<void>(operation_pointer);
    operation->deadline_registered = false;
    operation->complete(-1, error);
  }
  m_deferred_completions.clear();
  m_deadlines.clear();
  m_pending.clear();
  m_stop_after_pending = true;
}

void
SocketIoService::run()
{
  while (!m_stop_after_pending || !m_pending.empty()) {
    drain_completions();
    auto const now = Clock::now();
    expire_deadlines(now);
    if (!submit_pending()) {
      fail_service(errno);
      break;
    }
    if (m_stop_after_pending && m_pending.empty()) {
      break;
    }
    if (!m_deferred_completions.empty()) {
      continue;
    }

    io_uring_cqe *completion = nullptr;
    auto const wait_duration = time_until_next_deadline(now);
    int result = 0;
    if (wait_duration == chrono::nanoseconds::max()) {
      result = io_uring_wait_cqe(&m_ring, &completion);
    } else {
      __kernel_timespec timeout = {
          .tv_sec = chrono::duration_cast<chrono::seconds>(wait_duration).count(),
          .tv_nsec = (wait_duration % chrono::seconds{1}).count(),
      };
      result = io_uring_wait_cqe_timeout(&m_ring, &completion, &timeout);
    }

    if (result == 0) {
      auto const completed_entry = *completion;
      io_uring_cqe_seen(&m_ring, completion);
      process_completion(completed_entry);
    } else if (result != -ETIME && result != -EINTR) {
      fail_service(-result);
      break;
    }
  }
}
#endif

swoc::Rv<SocketIoMode>
parse_socket_io_mode(TextView value)
{
  swoc::Rv<SocketIoMode> result{SocketIoMode::AUTO};
  if (value == "auto"_tv) {
    result = SocketIoMode::AUTO;
  } else if (value == "off"_tv) {
    result = SocketIoMode::OFF;
  } else if (value == "required"_tv) {
    result = SocketIoMode::REQUIRED;
  } else {
    result.note(
        S_ERROR,
        R"(Invalid --io-uring value "{}". Expected auto, off, or required.)",
        value);
  }
  return result;
}

swoc::Rv<SocketIoBackend>
configure_socket_io(TextView value)
{
  swoc::Rv<SocketIoBackend> result{SocketIoBackend::POLL};
  auto &&[mode, mode_errata] = parse_socket_io_mode(value);
  result.note(std::move(mode_errata));
  if (!result.is_ok()) {
    return result;
  }

  auto &&[backend, backend_errata] = configure_socket_io(mode);
  result.result() = backend;
  result.note(std::move(backend_errata));
  if (!result.is_ok()) {
    return result;
  }

  auto const &service = socket_io_service();
  if (backend == SocketIoBackend::POLL && mode == SocketIoMode::AUTO) {
    result.note(
        S_INFO,
        "Using the poll(2) socket I/O backend because io_uring is unavailable: {}.",
        service.failure_reason());
  } else {
    result.note(S_INFO, "Using the {} socket I/O backend.", socket_io_backend_name(backend));
  }
  return result;
}

swoc::Rv<SocketIoBackend>
configure_socket_io(SocketIoMode mode)
{
  auto &service = socket_io_service(mode);
  swoc::Rv<SocketIoBackend> result{service.backend()};
  if (mode == SocketIoMode::REQUIRED && service.backend() != SocketIoBackend::IO_URING) {
    result.note(S_ERROR, "io_uring is required but unavailable: {}.", service.failure_reason());
  }
  return result;
}

TextView
socket_io_backend_name(SocketIoBackend backend)
{
  return backend == SocketIoBackend::IO_URING ? "io_uring"_tv : "poll"_tv;
}

int
poll_for_socket_io(int fd, chrono::milliseconds timeout, short events)
{
  auto &service = socket_io_service();
  if (timeout.count() <= 0) {
    return poll_with_system_call(fd, timeout, events);
  }
  if (service.backend() == SocketIoBackend::IO_URING) {
    auto const start_time = chrono::steady_clock::now();
    auto const result = service.poll(fd, timeout, events);
    if (result >= 0) {
      return result;
    }
    if (!service.fallback_allowed()) {
      return result;
    }
    timeout -=
        chrono::duration_cast<chrono::milliseconds>(chrono::steady_clock::now() - start_time);
  } else if (!service.fallback_allowed()) {
    errno = EIO;
    return -1;
  }
  return poll_with_system_call(fd, timeout, events);
}
