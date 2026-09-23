cmake_minimum_required(VERSION 3.16)

project(tlsrepair VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(tlsrepair_static STATIC
    src/tlsrepair.c
)

add_library(tlsrepair_shared SHARED
    src/tlsrepair.c
)

target_include_directories(tlsrepair_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/tlsrepair>
)

target_include_directories(tlsrepair_shared
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/tlsrepair>
)

target_link_libraries(tlsrepair_static
    PUBLIC
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_link_libraries(tlsrepair_shared
    PUBLIC
        CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto
)

set_target_properties(tlsrepair_static PROPERTIES
    OUTPUT_NAME tlsrepair
    EXPORT_NAME tlsrepair_static
)

set_target_properties(tlsrepair_shared PROPERTIES
    OUTPUT_NAME tlsrepair
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    EXPORT_NAME tlsrepair
)

add_executable(tlsrepair_test_static
    tests/tlsrepair_test.c
)

target_include_directories(tlsrepair_test_static
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(tlsrepair_test_static
    PRIVATE
        tlsrepair_static
)

add_executable(tlsrepair_test_shared
    tests/tlsrepair_test.c
)

target_include_directories(tlsrepair_test_shared
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(tlsrepair_test_shared
    PRIVATE
        tlsrepair_shared
)

set_target_properties(tlsrepair_test_shared PROPERTIES
    BUILD_RPATH "${CMAKE_BINARY_DIR}"
)

configure_package_config_file(
    cmake/tlsrepairConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/tlsrepairConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tlsrepair
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/tlsrepairConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        include/tlsrepair.h
    DESTINATION
        ${CMAKE_INSTALL_INCLUDEDIR}/tlsrepair
)

install(
    TARGETS tlsrepair_static tlsrepair_shared
    EXPORT tlsrepairTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
    EXPORT tlsrepairTargets
    FILE tlsrepairTargets.cmake
    NAMESPACE tlsrepair::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tlsrepair
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/tlsrepairConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/tlsrepairConfigVersion.cmake
    DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/cmake/tlsrepair
)