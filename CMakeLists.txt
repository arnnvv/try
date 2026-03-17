cmake_minimum_required(VERSION 3.20)

project(tcp_server LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(tcp_server main.cpp)

target_compile_options(
  tcp_server
  PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wformat=2
    -Wnull-dereference
    -Wimplicit-fallthrough
    -Wextra-semi
    -Wnon-virtual-dtor
    -fno-rtti
    -O2
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  option(TCP_SERVER_ENABLE_IO_URING "Build io_uring backend when liburing is available" ON)

  if(TCP_SERVER_ENABLE_IO_URING)
    find_package(PkgConfig QUIET)

    if(PkgConfig_FOUND)
      pkg_check_modules(LIBURING IMPORTED_TARGET liburing)
    endif()

    if(LIBURING_FOUND)
      target_compile_definitions(tcp_server PRIVATE TCP_SERVER_ENABLE_IO_URING=1)
      target_link_libraries(tcp_server PRIVATE PkgConfig::LIBURING)
    else()
      message(STATUS "liburing not found; building without io_uring backend")
    endif()
  endif()
endif()
