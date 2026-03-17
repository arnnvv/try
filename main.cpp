#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
    defined(__OpenBSD__)
#include <sys/event.h>
#endif

#include <array>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace {

constexpr std::uint16_t default_port = 8080;
constexpr std::size_t max_events = 256;
constexpr std::size_t read_buffer_size = 64 * 1024;

#if defined(TCP_SERVER_ENABLE_IO_URING)
#endif

class unique_fd {
public:
  unique_fd() noexcept = default;

  explicit unique_fd(int fd) noexcept : fd_(fd) {}

  ~unique_fd() { reset(); }

  unique_fd(const unique_fd &) = delete;
  unique_fd &operator=(const unique_fd &) = delete;

  unique_fd(unique_fd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

  unique_fd &operator=(unique_fd &&other) noexcept {
    if (this != &other) {
      reset(std::exchange(other.fd_, -1));
    }
    return *this;
  }

  [[nodiscard]] int get() const noexcept { return fd_; }

  [[nodiscard]] explicit operator bool() const noexcept { return fd_ != -1; }

  [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }

  void reset(int fd = -1) noexcept {
    if (fd_ != -1) {
      ::close(fd_);
    }
    fd_ = fd;
  }

private:
  int fd_ = -1;
};

enum class RequestedBackend {
  auto_select,
  poll,
  io_uring,
};

struct ProgramOptions {
  std::uint16_t port = default_port;
  RequestedBackend backend = RequestedBackend::auto_select;
};

[[noreturn]] void throw_system_error(std::string_view operation,
                                     int error = errno) {
  throw std::system_error(error, std::generic_category(),
                          std::string(operation));
}

#if defined(__linux__) || defined(TCP_SERVER_ENABLE_IO_URING)
[[nodiscard]] std::string errno_message(int error) {
  return std::generic_category().message(error);
}
#endif

#if defined(TCP_SERVER_ENABLE_IO_URING)
[[nodiscard]] std::string negative_result_message(int result) {
  return errno_message(-result);
}
#endif

void set_close_on_exec(int fd) {
  const int flags = ::fcntl(fd, F_GETFD, 0);
  if (flags == -1) {
    throw_system_error("fcntl(F_GETFD)");
  }

  if (::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1) {
    throw_system_error("fcntl(F_SETFD)");
  }
}

void set_non_blocking(int fd) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    throw_system_error("fcntl(F_GETFL)");
  }

  if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    throw_system_error("fcntl(F_SETFL)");
  }
}

void set_socket_option(int fd, int level, int option, int value) {
  if (::setsockopt(fd, level, option, &value, sizeof(value)) == -1) {
    throw_system_error("setsockopt");
  }
}

void configure_client_socket(int fd) {
  set_socket_option(fd, IPPROTO_TCP, TCP_NODELAY, 1);

#ifdef SO_NOSIGPIPE
  set_socket_option(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
#endif
}

#if defined(__linux__)
[[nodiscard]] int accepted_socket_flags() noexcept {
  return SOCK_NONBLOCK | SOCK_CLOEXEC;
}
#endif

[[nodiscard]] unique_fd create_listening_socket(std::uint16_t port) {
  unique_fd server(::socket(AF_INET, SOCK_STREAM, 0));
  if (!server) {
    throw_system_error("socket");
  }

  set_close_on_exec(server.get());
  set_non_blocking(server.get());
  set_socket_option(server.get(), SOL_SOCKET, SO_REUSEADDR, 1);

#ifdef SO_REUSEPORT
  set_socket_option(server.get(), SOL_SOCKET, SO_REUSEPORT, 1);
#endif

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_ANY);

  if (::bind(server.get(), reinterpret_cast<sockaddr *>(&address),
             sizeof(address)) == -1) {
    throw_system_error("bind");
  }

  if (::listen(server.get(), SOMAXCONN) == -1) {
    throw_system_error("listen");
  }

  return server;
}

[[nodiscard]] std::string format_endpoint(const sockaddr_in &address) {
  std::array<char, INET_ADDRSTRLEN> ip{};
  const char *result =
      ::inet_ntop(AF_INET, &address.sin_addr, ip.data(), ip.size());
  if (result == nullptr) {
    return "<unknown>";
  }

  return std::string(result) + ":" + std::to_string(ntohs(address.sin_port));
}

struct accepted_client {
  unique_fd socket;
  std::string endpoint;
};

[[nodiscard]] accepted_client accept_client(int listener_fd) {
  while (true) {
    sockaddr_in peer_address{};
    socklen_t peer_address_size = sizeof(peer_address);

#if defined(__linux__)
    const int client_fd =
        ::accept4(listener_fd, reinterpret_cast<sockaddr *>(&peer_address),
                  &peer_address_size, accepted_socket_flags());
#else
    const int client_fd =
        ::accept(listener_fd, reinterpret_cast<sockaddr *>(&peer_address),
                 &peer_address_size);
#endif
    if (client_fd >= 0) {
#if !defined(__linux__)
      set_close_on_exec(client_fd);
      set_non_blocking(client_fd);
#endif
      configure_client_socket(client_fd);
      return {unique_fd(client_fd), format_endpoint(peer_address)};
    }

    if (errno == EINTR) {
      continue;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return {};
    }

    throw_system_error("accept");
  }
}

[[nodiscard]] std::uint16_t parse_port_value(std::string_view value) {
  std::uint16_t port = 0;
  const auto [ptr, error] =
      std::from_chars(value.data(), value.data() + value.size(), port);
  if (error != std::errc{} || ptr != value.data() + value.size() || port == 0) {
    throw std::runtime_error("port must be an integer between 1 and 65535");
  }

  return port;
}

[[nodiscard]] RequestedBackend parse_backend_value(std::string_view value) {
  if (value == "auto") {
    return RequestedBackend::auto_select;
  }
  if (value == "poll") {
    return RequestedBackend::poll;
  }
  if (value == "io_uring") {
    return RequestedBackend::io_uring;
  }

  throw std::runtime_error("backend must be auto, poll, or io_uring");
}

[[nodiscard]] ProgramOptions parse_options(int argc, char *argv[]) {
  ProgramOptions options{};
  bool saw_port = false;

  for (int index = 1; index < argc; ++index) {
    const std::string_view argument{argv[index]};

    if (argument == "--help") {
      throw std::runtime_error(
          "usage: ./tcp_server [port] [--backend auto|poll|io_uring]");
    }

    if (argument == "--backend") {
      ++index;
      if (index >= argc) {
        throw std::runtime_error("missing value after --backend");
      }
      options.backend = parse_backend_value(argv[index]);
      continue;
    }

    constexpr std::string_view backend_prefix = "--backend=";
    if (argument.starts_with(backend_prefix)) {
      options.backend =
          parse_backend_value(argument.substr(backend_prefix.size()));
      continue;
    }

    if (argument.starts_with("--")) {
      throw std::runtime_error("unknown option: " + std::string(argument));
    }

    if (saw_port) {
      throw std::runtime_error(
          "usage: ./tcp_server [port] [--backend auto|poll|io_uring]");
    }

    options.port = parse_port_value(argument);
    saw_port = true;
  }

  return options;
}

struct ReadyEvent {
  int fd = -1;
  bool readable = false;
  bool writable = false;
  bool remote_closed = false;
  bool error = false;
};

class Poller {
public:
#if defined(__linux__)
  using native_event = epoll_event;
#else
  using native_event = struct kevent;
#endif

  Poller() {
#if defined(__linux__)
    unique_fd handle(::epoll_create1(EPOLL_CLOEXEC));
#else
    unique_fd handle(::kqueue());
#endif
    if (!handle) {
      throw_system_error("poller_create");
    }

#if !defined(__linux__)
    set_close_on_exec(handle.get());
#endif

    handle_ = std::move(handle);
  }

  void add(int fd) {
#if defined(__linux__)
    update_epoll(fd, false, EPOLL_CTL_ADD);
#else
    std::array<struct kevent, 2> changes{};
    EV_SET(&changes[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, nullptr);
    EV_SET(&changes[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR | EV_DISABLE, 0, 0,
           nullptr);
    submit(changes);
#endif
  }

  void set_write_interest(int fd, bool enabled) {
#if defined(__linux__)
    update_epoll(fd, enabled, EPOLL_CTL_MOD);
#else
    struct kevent change{};
    EV_SET(&change, fd, EVFILT_WRITE, enabled ? EV_ENABLE : EV_DISABLE, 0, 0,
           nullptr);
    submit(std::span{&change, std::size_t{1}});
#endif
  }

  void remove(int fd) noexcept {
#if defined(__linux__)
    if (::epoll_ctl(handle_.get(), EPOLL_CTL_DEL, fd, nullptr) == -1) {
      const int error = errno;
      if (error != ENOENT && error != EBADF) {
        std::cerr << "epoll_ctl(DEL) failed for fd " << fd << ": "
                  << errno_message(error) << '\n';
      }
    }
#else
    std::array<struct kevent, 2> changes{};
    EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    const timespec timeout{0, 0};
    (void)::kevent(handle_.get(), changes.data(),
                   static_cast<int>(changes.size()), nullptr, 0, &timeout);
#endif
  }

  [[nodiscard]] int wait(std::span<native_event> events, int timeout_ms) const {
    while (true) {
#if defined(__linux__)
      const int ready =
          ::epoll_wait(handle_.get(), events.data(),
                       static_cast<int>(events.size()), timeout_ms);
#else
      timespec timeout{};
      timespec *timeout_ptr = nullptr;
      if (timeout_ms >= 0) {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_nsec = (timeout_ms % 1000) * 1'000'000;
        timeout_ptr = &timeout;
      }

      const int ready = ::kevent(handle_.get(), nullptr, 0, events.data(),
                                 static_cast<int>(events.size()), timeout_ptr);
#endif
      if (ready >= 0) {
        return ready;
      }

      if (errno == EINTR) {
        continue;
      }

      throw_system_error("poll_wait");
    }
  }

  [[nodiscard]] static ReadyEvent
  translate(const native_event &event) noexcept {
    ReadyEvent ready{};
#if defined(__linux__)
    ready.fd = event.data.fd;
    ready.readable = (event.events & EPOLLIN) != 0;
    ready.writable = (event.events & EPOLLOUT) != 0;
    ready.remote_closed = (event.events & EPOLLRDHUP) != 0;
    ready.error = (event.events & (EPOLLERR | EPOLLHUP)) != 0;
#else
    ready.fd = static_cast<int>(event.ident);
    ready.readable = event.filter == EVFILT_READ;
    ready.writable = event.filter == EVFILT_WRITE;
    ready.remote_closed = (event.flags & EV_EOF) != 0;
    ready.error = (event.flags & EV_ERROR) != 0;
#endif
    return ready;
  }

private:
#if defined(__linux__)
  static constexpr std::uint32_t base_events = EPOLLIN | EPOLLET | EPOLLRDHUP;

  void update_epoll(int fd, bool write_enabled, int operation) {
    epoll_event event{};
    event.events = base_events | (write_enabled ? EPOLLOUT : 0U);
    event.data.fd = fd;

    if (::epoll_ctl(handle_.get(), operation, fd, &event) == -1) {
      throw_system_error("epoll_ctl");
    }
  }
#else
  void submit(std::span<struct kevent> changes) {
    const timespec timeout{0, 0};
    if (::kevent(handle_.get(), changes.data(),
                 static_cast<int>(changes.size()), nullptr, 0,
                 &timeout) == -1) {
      throw_system_error("kevent");
    }
  }
#endif

  unique_fd handle_;
};

struct PollConnection {
  PollConnection(unique_fd socket_fd, std::string peer_name) noexcept
      : socket(std::move(socket_fd)), peer(std::move(peer_name)) {}

  [[nodiscard]] int fd() const noexcept { return socket.get(); }

  [[nodiscard]] bool wants_write() const noexcept {
    return write_offset < pending_output.size();
  }

  unique_fd socket;
  std::string peer;
  std::string pending_output;
  std::size_t write_offset = 0;
  bool read_closed = false;
};

using PollConnectionMap = std::unordered_map<int, PollConnection>;

[[nodiscard]] constexpr int send_flags() noexcept {
#ifdef MSG_NOSIGNAL
  return MSG_NOSIGNAL;
#else
  return 0;
#endif
}

void register_client(Poller &poller, PollConnectionMap &connections,
                     accepted_client client) {
  const int fd = client.socket.get();
  poller.add(fd);

  try {
    const auto [_, inserted] = connections.try_emplace(
        fd, std::move(client.socket), std::move(client.endpoint));
    if (!inserted) {
      throw std::runtime_error("duplicate file descriptor");
    }
  } catch (...) {
    poller.remove(fd);
    throw;
  }
}

void close_connection(Poller &poller, PollConnectionMap &connections, int fd,
                      std::string_view reason) noexcept {
  const auto connection_it = connections.find(fd);
  if (connection_it == connections.end()) {
    return;
  }

  std::cout << "closed connection from " << connection_it->second.peer
            << " fd=" << fd << " reason=" << reason << '\n';
  poller.remove(fd);
  connections.erase(connection_it);
}

void accept_pending_clients(Poller &poller, PollConnectionMap &connections,
                            int listener_fd) {
  while (true) {
    accepted_client client = accept_client(listener_fd);
    if (!client.socket) {
      return;
    }

    std::cout << "accepted connection from " << client.endpoint
              << " fd=" << client.socket.get() << '\n';
    register_client(poller, connections, std::move(client));
  }
}

enum class ReadResult {
  open,
  remote_closed,
  error,
};

[[nodiscard]] ReadResult read_into_output(PollConnection &connection) {
  std::array<char, read_buffer_size> buffer{};

  while (true) {
    const ssize_t bytes_read =
        ::recv(connection.fd(), buffer.data(), buffer.size(), 0);

    if (bytes_read > 0) {
      connection.pending_output.append(buffer.data(),
                                       static_cast<std::size_t>(bytes_read));
      continue;
    }

    if (bytes_read == 0) {
      return ReadResult::remote_closed;
    }

    if (errno == EINTR) {
      continue;
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return ReadResult::open;
    }

    return ReadResult::error;
  }
}

[[nodiscard]] bool flush_output(PollConnection &connection) {
  while (connection.wants_write()) {
    const char *data =
        connection.pending_output.data() + connection.write_offset;
    const std::size_t bytes_left =
        connection.pending_output.size() - connection.write_offset;

    const ssize_t bytes_sent =
        ::send(connection.fd(), data, bytes_left, send_flags());

    if (bytes_sent > 0) {
      connection.write_offset += static_cast<std::size_t>(bytes_sent);
      continue;
    }

    if (bytes_sent == -1 && errno == EINTR) {
      continue;
    }

    if (bytes_sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      break;
    }

    return false;
  }

  if (!connection.wants_write()) {
    connection.pending_output.clear();
    connection.write_offset = 0;
  } else if (connection.write_offset >= 64 * 1024) {
    connection.pending_output.erase(0, connection.write_offset);
    connection.write_offset = 0;
  }

  return true;
}

void run_poll_server(std::uint16_t port) {
  unique_fd listener = create_listening_socket(port);

  Poller poller;
  poller.add(listener.get());

  PollConnectionMap connections;
  connections.reserve(1024);

  std::array<Poller::native_event, max_events> events{};

  std::cout << "listening on 0.0.0.0:" << port << " backend=poll\n";

  while (true) {
    const int ready = poller.wait(events, -1);

    for (int index = 0; index < ready; ++index) {
      const ReadyEvent event =
          Poller::translate(events[static_cast<std::size_t>(index)]);

      if (event.fd == listener.get()) {
        accept_pending_clients(poller, connections, listener.get());
        continue;
      }

      auto connection_it = connections.find(event.fd);
      if (connection_it == connections.end()) {
        continue;
      }

      PollConnection &connection = connection_it->second;
      bool keep_open = true;

      if (event.readable) {
        switch (read_into_output(connection)) {
        case ReadResult::open:
          break;
        case ReadResult::remote_closed:
          connection.read_closed = true;
          break;
        case ReadResult::error:
          keep_open = false;
          break;
        }
      }

      if (keep_open && (event.writable || connection.wants_write())) {
        keep_open = flush_output(connection);
      }

      if (event.remote_closed) {
        connection.read_closed = true;
      }

      if (connection.read_closed && !connection.wants_write()) {
        close_connection(poller, connections, event.fd, "remote-closed");
        continue;
      }

      if (!keep_open || event.error) {
        close_connection(poller, connections, event.fd,
                         event.error ? "poll-error" : "socket-closed");
        continue;
      }

      poller.set_write_interest(event.fd, connection.wants_write());
    }
  }
}

#if defined(TCP_SERVER_ENABLE_IO_URING)

struct UringConnection {
  UringConnection(unique_fd socket_fd, std::string peer_name) noexcept
      : socket(std::move(socket_fd)), peer(std::move(peer_name)) {}

  [[nodiscard]] int fd() const noexcept { return socket.get(); }

  unique_fd socket;
  std::string peer;
  std::array<char, read_buffer_size> read_buffer{};
  std::deque<std::string> pending_chunks;
  std::size_t front_offset = 0;
  bool recv_pending = false;
  bool send_pending = false;
  bool closing = false;
  bool read_closed = false;
};

enum class UringOp {
  accept,
  recv,
  send,
};

struct UringRequest {
  explicit UringRequest(UringOp operation) noexcept : op(operation) {}

  UringOp op;
  std::shared_ptr<UringConnection> connection;
  sockaddr_in peer_address{};
  socklen_t peer_address_size = sizeof(peer_address);
};

class IoUringServer {
public:
  explicit IoUringServer(std::uint16_t port)
      : listener_(create_listening_socket(port)) {
    io_uring_params params{};
    params.flags = 0;
    params.cq_entries = io_uring_cq_entries;

    const int result =
        ::io_uring_queue_init_params(io_uring_entries, &ring_, &params);
    if (result < 0) {
      throw std::runtime_error("io_uring_queue_init_params: " +
                               negative_result_message(result));
    }
  }

  ~IoUringServer() { ::io_uring_queue_exit(&ring_); }

  IoUringServer(const IoUringServer &) = delete;
  IoUringServer &operator=(const IoUringServer &) = delete;

  void run() {
    std::cout << "listening on 0.0.0.0:" << port() << " backend=io_uring\n";
    queue_accept();

    while (true) {
      io_uring_cqe *cqe = nullptr;
      const int wait_result = ::io_uring_wait_cqe(&ring_, &cqe);
      if (wait_result < 0) {
        throw std::runtime_error("io_uring_wait_cqe: " +
                                 negative_result_message(wait_result));
      }

      while (cqe != nullptr) {
        handle_completion(cqe);
        ::io_uring_cqe_seen(&ring_, cqe);

        cqe = nullptr;
        if (::io_uring_peek_cqe(&ring_, &cqe) != 0) {
          break;
        }
      }
    }
  }

private:
  using RequestMap =
      std::unordered_map<UringRequest *, std::unique_ptr<UringRequest>>;
  using ConnectionMap =
      std::unordered_map<int, std::shared_ptr<UringConnection>>;

  [[nodiscard]] std::uint16_t port() const noexcept {
    sockaddr_in address{};
    socklen_t size = sizeof(address);
    if (::getsockname(listener_.get(), reinterpret_cast<sockaddr *>(&address),
                      &size) == -1) {
      return 0;
    }
    return ntohs(address.sin_port);
  }

  [[nodiscard]] io_uring_sqe *acquire_sqe() {
    io_uring_sqe *sqe = ::io_uring_get_sqe(&ring_);
    if (sqe != nullptr) {
      return sqe;
    }

    const int submit_result = ::io_uring_submit(&ring_);
    if (submit_result < 0) {
      throw std::runtime_error("io_uring_submit: " +
                               negative_result_message(submit_result));
    }

    sqe = ::io_uring_get_sqe(&ring_);
    if (sqe == nullptr) {
      throw std::runtime_error("io_uring SQ ring exhausted");
    }
    return sqe;
  }

  void submit_request(UringRequest *request,
                      std::unique_ptr<UringRequest> owned) {
    pending_requests_.emplace(request, std::move(owned));

    const int submit_result = ::io_uring_submit(&ring_);
    if (submit_result < 0) {
      pending_requests_.erase(request);
      throw std::runtime_error("io_uring_submit: " +
                               negative_result_message(submit_result));
    }
  }

  void queue_accept() {
    auto request = std::make_unique<UringRequest>(UringOp::accept);
    UringRequest *raw_request = request.get();

    io_uring_sqe *sqe = acquire_sqe();
    ::io_uring_prep_accept(
        sqe, listener_.get(),
        reinterpret_cast<sockaddr *>(&raw_request->peer_address),
        &raw_request->peer_address_size, accepted_socket_flags());
    ::io_uring_sqe_set_data(sqe, raw_request);

    submit_request(raw_request, std::move(request));
  }

  void queue_recv(const std::shared_ptr<UringConnection> &connection) {
    if (connection->closing || connection->recv_pending) {
      return;
    }

    auto request = std::make_unique<UringRequest>(UringOp::recv);
    request->connection = connection;
    UringRequest *raw_request = request.get();

    io_uring_sqe *sqe = acquire_sqe();
    ::io_uring_prep_recv(sqe, connection->fd(), connection->read_buffer.data(),
                         connection->read_buffer.size(), 0);
#ifdef IORING_RECVSEND_POLL_FIRST
    sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
#endif
    ::io_uring_sqe_set_data(sqe, raw_request);

    connection->recv_pending = true;
    submit_request(raw_request, std::move(request));
  }

  void queue_send(const std::shared_ptr<UringConnection> &connection) {
    if (connection->closing || connection->send_pending ||
        connection->pending_chunks.empty()) {
      return;
    }

    auto request = std::make_unique<UringRequest>(UringOp::send);
    request->connection = connection;
    UringRequest *raw_request = request.get();

    const std::string &chunk = connection->pending_chunks.front();
    const char *data = chunk.data() + connection->front_offset;
    const std::size_t bytes_left = chunk.size() - connection->front_offset;

    io_uring_sqe *sqe = acquire_sqe();
    ::io_uring_prep_send(sqe, connection->fd(), data, bytes_left, send_flags());
#ifdef IORING_RECVSEND_POLL_FIRST
    sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
#endif
    ::io_uring_sqe_set_data(sqe, raw_request);

    connection->send_pending = true;
    submit_request(raw_request, std::move(request));
  }

  void close_connection(const std::shared_ptr<UringConnection> &connection,
                        std::string_view reason) {
    if (connection->closing) {
      return;
    }

    connection->closing = true;
    connections_.erase(connection->fd());
    std::cout << "closed connection from " << connection->peer
              << " fd=" << connection->fd() << " reason=" << reason << '\n';
  }

  void
  maybe_finish_connection(const std::shared_ptr<UringConnection> &connection) {
    if (!connection->closing) {
      return;
    }
    if (connection->recv_pending || connection->send_pending) {
      return;
    }

    connection->socket.reset();
    connection->pending_chunks.clear();
    connection->front_offset = 0;
  }

  void consume_sent_bytes(UringConnection &connection, std::size_t bytes_sent) {
    while (bytes_sent > 0 && !connection.pending_chunks.empty()) {
      std::string &front = connection.pending_chunks.front();
      const std::size_t available = front.size() - connection.front_offset;
      if (bytes_sent < available) {
        connection.front_offset += bytes_sent;
        return;
      }

      bytes_sent -= available;
      connection.pending_chunks.pop_front();
      connection.front_offset = 0;
    }
  }

  void handle_accept(UringRequest &request, int result) {
    queue_accept();

    if (result < 0) {
      switch (-result) {
      case EAGAIN:
      case EWOULDBLOCK:
      case EINTR:
      case ECONNABORTED:
      case EPROTO:
        return;
      default:
        throw std::runtime_error("io_uring accept failed: " +
                                 negative_result_message(result));
      }
    }

    unique_fd client_fd(result);
    configure_client_socket(client_fd.get());

    auto connection = std::make_shared<UringConnection>(
        std::move(client_fd), format_endpoint(request.peer_address));
    const int fd = connection->fd();
    const auto [_, inserted] = connections_.try_emplace(fd, connection);
    if (!inserted) {
      throw std::runtime_error("duplicate file descriptor");
    }

    std::cout << "accepted connection from " << connection->peer << " fd=" << fd
              << '\n';
    queue_recv(connection);
  }

  void handle_recv(UringRequest &request, int result) {
    const std::shared_ptr<UringConnection> connection = request.connection;
    connection->recv_pending = false;

    if (connection->closing) {
      maybe_finish_connection(connection);
      return;
    }

    if (result == 0) {
      connection->read_closed = true;
      if (connection->pending_chunks.empty() && !connection->send_pending) {
        close_connection(connection, "remote-closed");
        maybe_finish_connection(connection);
      }
      return;
    }

    if (result < 0) {
      close_connection(connection, "recv-error");
      maybe_finish_connection(connection);
      return;
    }

    connection->pending_chunks.emplace_back(connection->read_buffer.data(),
                                            static_cast<std::size_t>(result));

    if (!connection->read_closed) {
      queue_recv(connection);
    }
    queue_send(connection);
  }

  void handle_send(UringRequest &request, int result) {
    const std::shared_ptr<UringConnection> connection = request.connection;
    connection->send_pending = false;

    if (result <= 0) {
      close_connection(connection, result == 0 ? "send-closed" : "send-error");
      maybe_finish_connection(connection);
      return;
    }

    consume_sent_bytes(*connection, static_cast<std::size_t>(result));

    if (connection->closing) {
      maybe_finish_connection(connection);
      return;
    }

    if (connection->read_closed && connection->pending_chunks.empty()) {
      close_connection(connection, "remote-closed");
      maybe_finish_connection(connection);
      return;
    }

    if (!connection->pending_chunks.empty()) {
      queue_send(connection);
    }
  }

  void handle_completion(io_uring_cqe *cqe) {
    auto *request = static_cast<UringRequest *>(::io_uring_cqe_get_data(cqe));
    const auto request_it = pending_requests_.find(request);
    if (request_it == pending_requests_.end()) {
      return;
    }

    std::unique_ptr<UringRequest> owned_request = std::move(request_it->second);
    pending_requests_.erase(request_it);

    switch (owned_request->op) {
    case UringOp::accept:
      handle_accept(*owned_request, cqe->res);
      break;
    case UringOp::recv:
      handle_recv(*owned_request, cqe->res);
      break;
    case UringOp::send:
      handle_send(*owned_request, cqe->res);
      break;
    }
  }

  io_uring ring_{};
  unique_fd listener_;
  RequestMap pending_requests_;
  ConnectionMap connections_;
};

void run_io_uring_server(std::uint16_t port) {
  IoUringServer server(port);
  server.run();
}

#else

[[noreturn]] void run_io_uring_server(std::uint16_t) {
  throw std::runtime_error(
      "io_uring backend was not built; use --backend poll or build on Linux "
      "with liburing available");
}

#endif

void run_server(const ProgramOptions &options) {
  switch (options.backend) {
  case RequestedBackend::poll:
    run_poll_server(options.port);
    return;
  case RequestedBackend::io_uring:
    run_io_uring_server(options.port);
    return;
  case RequestedBackend::auto_select:
#if defined(TCP_SERVER_ENABLE_IO_URING)
    try {
      run_io_uring_server(options.port);
      return;
    } catch (const std::exception &error) {
      std::cerr << "io_uring unavailable, falling back to poll: "
                << error.what() << '\n';
    }
#endif
    run_poll_server(options.port);
    return;
  }
}

} // namespace

int main(int argc, char *argv[]) {
  try {
    const ProgramOptions options = parse_options(argc, argv);
    run_server(options);
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
