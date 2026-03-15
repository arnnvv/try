#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__linux__)
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/event.h>
#else
#endif

#include <array>
#include <charconv>
#include <cerrno>
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

namespace
{

constexpr std::uint16_t default_port = 8080;
constexpr std::size_t max_events = 256;
constexpr std::size_t read_buffer_size = 64 * 1024;

class unique_fd
{
public:
    unique_fd() noexcept = default;

    explicit unique_fd(int fd) noexcept : fd_(fd) {}

    ~unique_fd()
    {
        reset();
    }

    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

    unique_fd(unique_fd&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}

    unique_fd& operator=(unique_fd&& other) noexcept
    {
        if (this != &other)
        {
            reset(std::exchange(other.fd_, -1));
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept
    {
        return fd_;
    }

    [[nodiscard]] explicit operator bool() const noexcept
    {
        return fd_ != -1;
    }

    [[nodiscard]] int release() noexcept
    {
        return std::exchange(fd_, -1);
    }

    void reset(int fd = -1) noexcept
    {
        if (fd_ != -1)
        {
            ::close(fd_);
        }
        fd_ = fd;
    }

private:
    int fd_ = -1;
};

[[noreturn]] void throw_system_error(std::string_view operation, int error = errno)
{
    throw std::system_error(error, std::generic_category(), std::string(operation));
}

void set_close_on_exec(int fd)
{
    const int flags = ::fcntl(fd, F_GETFD, 0);
    if (flags == -1)
    {
        throw_system_error("fcntl(F_GETFD)");
    }

    if (::fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
    {
        throw_system_error("fcntl(F_SETFD)");
    }
}

void set_non_blocking(int fd)
{
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        throw_system_error("fcntl(F_GETFL)");
    }

    if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        throw_system_error("fcntl(F_SETFL)");
    }
}

void set_socket_option(int fd, int level, int option, int value)
{
    if (::setsockopt(fd, level, option, &value, sizeof(value)) == -1)
    {
        throw_system_error("setsockopt");
    }
}

void configure_client_socket(int fd)
{
    set_socket_option(fd, IPPROTO_TCP, TCP_NODELAY, 1);

#ifdef SO_NOSIGPIPE
    set_socket_option(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
#endif
}

[[nodiscard]] unique_fd create_listening_socket(std::uint16_t port)
{
    unique_fd server(::socket(AF_INET, SOCK_STREAM, 0));
    if (!server)
    {
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

    if (::bind(server.get(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == -1)
    {
        throw_system_error("bind");
    }

    if (::listen(server.get(), SOMAXCONN) == -1)
    {
        throw_system_error("listen");
    }

    return server;
}

[[nodiscard]] unique_fd accept_client(int listener_fd)
{
    while (true)
    {
#if defined(__linux__)
        const int client_fd = ::accept4(listener_fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        const int client_fd = ::accept(listener_fd, nullptr, nullptr);
#endif
        if (client_fd >= 0)
        {
#if !defined(__linux__)
            set_close_on_exec(client_fd);
            set_non_blocking(client_fd);
#endif
            configure_client_socket(client_fd);
            return unique_fd(client_fd);
        }

        if (errno == EINTR)
        {
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return {};
        }

        throw_system_error("accept");
    }
}

struct ReadyEvent
{
    int fd = -1;
    bool readable = false;
    bool writable = false;
    bool remote_closed = false;
    bool error = false;
};

class Poller
{
public:
#if defined(__linux__)
    using native_event = epoll_event;
#else
    using native_event = struct kevent;
#endif

    Poller()
    {
#if defined(__linux__)
        unique_fd handle(::epoll_create1(EPOLL_CLOEXEC));
#else
        unique_fd handle(::kqueue());
#endif
        if (!handle)
        {
            throw_system_error("poller_create");
        }

#if !defined(__linux__)
        set_close_on_exec(handle.get());
#endif

        handle_ = std::move(handle);
    }

    void add(int fd)
    {
#if defined(__linux__)
        update_epoll(fd, false, EPOLL_CTL_ADD);
#else
        std::array<struct kevent, 2> changes{};
        EV_SET(&changes[0], fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, nullptr);
        EV_SET(&changes[1], fd, EVFILT_WRITE, EV_ADD | EV_CLEAR | EV_DISABLE, 0, 0, nullptr);
        submit(changes);
#endif
    }

    void set_write_interest(int fd, bool enabled)
    {
#if defined(__linux__)
        update_epoll(fd, enabled, EPOLL_CTL_MOD);
#else
        struct kevent change{};
        EV_SET(&change, fd, EVFILT_WRITE, enabled ? EV_ENABLE : EV_DISABLE, 0, 0, nullptr);
        submit(std::span{&change, std::size_t{1}});
#endif
    }

    void remove(int fd) noexcept
    {
#if defined(__linux__)
        if (::epoll_ctl(handle_.get(), EPOLL_CTL_DEL, fd, nullptr) == -1)
        {
            const int error = errno;
            if (error != ENOENT && error != EBADF)
            {
                std::cerr << "epoll_ctl(DEL) failed for fd " << fd << ": "
                          << std::generic_category().message(error) << '\n';
            }
        }
#else
        std::array<struct kevent, 2> changes{};
        EV_SET(&changes[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&changes[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        const timespec timeout{0, 0};
        (void)::kevent(
            handle_.get(),
            changes.data(),
            static_cast<int>(changes.size()),
            nullptr,
            0,
            &timeout);
#endif
    }

    [[nodiscard]] int wait(std::span<native_event> events, int timeout_ms) const
    {
        while (true)
        {
#if defined(__linux__)
            const int ready = ::epoll_wait(
                handle_.get(),
                events.data(),
                static_cast<int>(events.size()),
                timeout_ms);
#else
            timespec timeout{};
            timespec* timeout_ptr = nullptr;
            if (timeout_ms >= 0)
            {
                timeout.tv_sec = timeout_ms / 1000;
                timeout.tv_nsec = (timeout_ms % 1000) * 1'000'000;
                timeout_ptr = &timeout;
            }

            const int ready = ::kevent(
                handle_.get(),
                nullptr,
                0,
                events.data(),
                static_cast<int>(events.size()),
                timeout_ptr);
#endif
            if (ready >= 0)
            {
                return ready;
            }

            if (errno == EINTR)
            {
                continue;
            }

            throw_system_error("poll_wait");
        }
    }

    [[nodiscard]] static ReadyEvent translate(const native_event& event) noexcept
    {
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

    void update_epoll(int fd, bool write_enabled, int operation)
    {
        epoll_event event{};
        event.events = base_events | (write_enabled ? EPOLLOUT : 0U);
        event.data.fd = fd;

        if (::epoll_ctl(handle_.get(), operation, fd, &event) == -1)
        {
            throw_system_error("epoll_ctl");
        }
    }
#else
    void submit(std::span<struct kevent> changes)
    {
        const timespec timeout{0, 0};
        if (::kevent(
                handle_.get(),
                changes.data(),
                static_cast<int>(changes.size()),
                nullptr,
                0,
                &timeout)
            == -1)
        {
            throw_system_error("kevent");
        }
    }
#endif

    unique_fd handle_;
};

struct Connection
{
    explicit Connection(unique_fd socket_fd) noexcept : socket(std::move(socket_fd)) {}

    [[nodiscard]] int fd() const noexcept
    {
        return socket.get();
    }

    [[nodiscard]] bool wants_write() const noexcept
    {
        return write_offset < pending_output.size();
    }

    unique_fd socket;
    std::string pending_output;
    std::size_t write_offset = 0;
};

using ConnectionMap = std::unordered_map<int, Connection>;

[[nodiscard]] constexpr int send_flags() noexcept
{
#ifdef MSG_NOSIGNAL
    return MSG_NOSIGNAL;
#else
    return 0;
#endif
}

void register_client(Poller& poller, ConnectionMap& connections, unique_fd client)
{
    const int fd = client.get();
    poller.add(fd);

    try
    {
        const auto [_, inserted] = connections.try_emplace(fd, std::move(client));
        if (!inserted)
        {
            throw std::runtime_error("duplicate file descriptor");
        }
    }
    catch (...)
    {
        poller.remove(fd);
        throw;
    }
}

void close_connection(Poller& poller, ConnectionMap& connections, int fd) noexcept
{
    poller.remove(fd);
    connections.erase(fd);
}

void accept_pending_clients(Poller& poller, ConnectionMap& connections, int listener_fd)
{
    while (true)
    {
        unique_fd client = accept_client(listener_fd);
        if (!client)
        {
            return;
        }

        register_client(poller, connections, std::move(client));
    }
}

[[nodiscard]] bool read_into_output(Connection& connection)
{
    std::array<char, read_buffer_size> buffer{};

    while (true)
    {
        const ssize_t bytes_read =
            ::recv(connection.fd(), buffer.data(), buffer.size(), 0);

        if (bytes_read > 0)
        {
            connection.pending_output.append(
                buffer.data(),
                static_cast<std::size_t>(bytes_read));
            continue;
        }

        if (bytes_read == 0)
        {
            return false;
        }

        if (errno == EINTR)
        {
            continue;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return true;
        }

        return false;
    }
}

[[nodiscard]] bool flush_output(Connection& connection)
{
    while (connection.wants_write())
    {
        const char* data = connection.pending_output.data() + connection.write_offset;
        const std::size_t bytes_left = connection.pending_output.size() - connection.write_offset;

        const ssize_t bytes_sent =
            ::send(connection.fd(), data, bytes_left, send_flags());

        if (bytes_sent > 0)
        {
            connection.write_offset += static_cast<std::size_t>(bytes_sent);
            continue;
        }

        if (bytes_sent == -1 && errno == EINTR)
        {
            continue;
        }

        if (bytes_sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            break;
        }

        return false;
    }

    if (!connection.wants_write())
    {
        connection.pending_output.clear();
        connection.write_offset = 0;
    }
    else if (connection.write_offset >= 64 * 1024)
    {
        connection.pending_output.erase(0, connection.write_offset);
        connection.write_offset = 0;
    }

    return true;
}

[[nodiscard]] std::uint16_t parse_port(int argc, char* argv[])
{
    if (argc == 1)
    {
        return default_port;
    }

    if (argc != 2)
    {
        throw std::runtime_error("usage: ./tcp_server [port]");
    }

    std::uint16_t port = 0;
    const std::string_view value{argv[1]};
    const auto [ptr, error] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || ptr != value.data() + value.size() || port == 0)
    {
        throw std::runtime_error("port must be an integer between 1 and 65535");
    }

    return port;
}

} // namespace

int main(int argc, char* argv[])
{
    try
    {
        const std::uint16_t port = parse_port(argc, argv);
        unique_fd listener = create_listening_socket(port);

        Poller poller;
        poller.add(listener.get());

        ConnectionMap connections;
        connections.reserve(1024);

        std::array<Poller::native_event, max_events> events{};

        std::cout << "listening on 0.0.0.0:" << port << '\n';

        while (true)
        {
            const int ready = poller.wait(events, -1);

            for (int index = 0; index < ready; ++index)
            {
                const ReadyEvent event = Poller::translate(events[static_cast<std::size_t>(index)]);

                if (event.fd == listener.get())
                {
                    accept_pending_clients(poller, connections, listener.get());
                    continue;
                }

                auto connection_it = connections.find(event.fd);
                if (connection_it == connections.end())
                {
                    continue;
                }

                Connection& connection = connection_it->second;
                bool keep_open = true;
                bool handled_io = false;

                if (event.readable)
                {
                    handled_io = true;
                    keep_open = read_into_output(connection);
                }

                if (keep_open && (event.writable || connection.wants_write()))
                {
                    handled_io = true;
                    keep_open = flush_output(connection);
                }

                if (!keep_open || event.error || (event.remote_closed && !handled_io))
                {
                    close_connection(poller, connections, event.fd);
                    continue;
                }

                poller.set_write_interest(event.fd, connection.wants_write());
            }
        }
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
