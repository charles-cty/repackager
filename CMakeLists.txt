cmake_minimum_required(VERSION 3.20)
project(repackager VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# This project does not use C++20 named modules. Scanning emits Ninja rules that
# some Windows ninja shims reject (`CXX_SCAN__..._$cfg` lexing error).
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

option(REPACKAGER_USE_MSIX_SDK "Fetch and link the pinned Microsoft MSIX SDK for package I/O" OFF)
option(REPACKAGER_BUILD_TESTS "Build unit and workflow tests" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(REPACKAGER_USE_MSIX_SDK)
  include(MSIXSDK)
  repackager_try_fetch_msix_sdk()
endif()

set(REPACKAGER_LIB_SOURCES
  src/error.cpp
  src/hash.cpp
  src/identity.cpp
  src/aumid.cpp
  src/paths.cpp
  src/xml.cpp
  src/json.cpp
  src/overlay.cpp
  src/receipt.cpp
  src/journal.cpp
  src/manifest.cpp
  src/compat.cpp
  src/pe.cpp
  src/zip.cpp
  src/report.cpp
  src/stage.cpp
  src/assets.cpp
  src/toolchain.cpp
  src/package_io.cpp
  src/register.cpp
  src/elevate.cpp
  src/cli.cpp
  src/operations.cpp
  src/workflows.cpp
)

if(WIN32)
  list(APPEND REPACKAGER_LIB_SOURCES
    src/win/msxml6.cpp
    src/win/wic_assets.cpp
    src/win/appx_packaging.cpp
    src/win/package_manager.cpp
    src/win/elevation.cpp
    src/win/pe_resources.cpp
  )
endif()

add_library(repackager_lib STATIC ${REPACKAGER_LIB_SOURCES})
target_include_directories(repackager_lib
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(repackager_lib
  PUBLIC
    REPACKAGER_VERSION="${PROJECT_VERSION}"
)

if(REPACKAGER_USE_MSIX_SDK)
  target_compile_definitions(repackager_lib PUBLIC REPACKAGER_USE_MSIX_SDK=1)
  if(TARGET repackager_msix_sdk)
    target_link_libraries(repackager_lib PUBLIC repackager_msix_sdk)
  endif()
endif()

if(MSVC)
  target_compile_options(repackager_lib PRIVATE /W4 /permissive- /utf-8 /EHsc)
  target_compile_definitions(repackager_lib PUBLIC UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(repackager_lib PUBLIC
    ole32 oleaut32 shell32 shlwapi advapi32 crypt32 version windowscodecs
    msxml6 runtimeobject windowsapp
  )
else()
  target_compile_options(repackager_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(repackager src/main.cpp)
target_link_libraries(repackager PRIVATE repackager_lib)
if(MSVC)
  target_compile_options(repackager PRIVATE /W4 /permissive- /utf-8 /EHsc)
else()
  target_compile_options(repackager PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(REPACKAGER_BUILD_TESTS)
  enable_testing()
  add_executable(repackager_tests
    tests/test_main.cpp
    tests/test_identity.cpp
    tests/test_xml.cpp
    tests/test_overlay.cpp
    tests/test_receipt.cpp
    tests/test_paths.cpp
    tests/test_aumid.cpp
    tests/test_compat.cpp
    tests/test_cli.cpp
    tests/test_pe.cpp
    tests/test_rollback.cpp
    tests/test_assets.cpp
    tests/test_toolchain.cpp
    tests/pe_builder.cpp
  )
  target_link_libraries(repackager_tests PRIVATE repackager_lib)
  target_include_directories(repackager_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  target_compile_definitions(repackager_tests PRIVATE
    REPACKAGER_EXE="$<TARGET_FILE:repackager>"
    REPACKAGER_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures"
  )
  add_dependencies(repackager_tests repackager)
  if(MSVC)
    target_compile_options(repackager_tests PRIVATE /W4 /permissive- /utf-8 /EHsc)
  else()
    target_compile_options(repackager_tests PRIVATE -Wall -Wextra -Wpedantic)
  endif()
  add_test(NAME repackager_tests COMMAND repackager_tests)
endif()
