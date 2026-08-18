# Optional pinned Microsoft MSIX SDK (package I/O only; registration stays on PackageManager).
# Enable with -DREPACKAGER_USE_MSIX_SDK=ON.
#
# The official tree is large (OpenSSL, tests, samples). We fetch a pinned commit and
# expose an imported interface target `repackager_msix_sdk` when the sources configure
# successfully. Callers must still compile our adapter; this file only pins the SDK.

set(REPACKAGER_MSIX_SDK_GIT_REPOSITORY "https://github.com/microsoft/msix-packaging.git")
# Pin: MSIX-Packaging 1.7 + later CMake fixes (2021-11-18).
set(REPACKAGER_MSIX_SDK_GIT_TAG "c3d4731d86a669a2a69d13350a1e40f1d6462895")

function(repackager_try_fetch_msix_sdk)
  if(NOT REPACKAGER_USE_MSIX_SDK)
    return()
  endif()

  include(FetchContent)
  set(SKIP_BUNDLES ON CACHE BOOL "" FORCE)
  set(MSIX_PACK UNPACK CACHE STRING "" FORCE)
  set(MSIX_SAMPLES OFF CACHE BOOL "" FORCE)
  set(MSIX_TESTS OFF CACHE BOOL "" FORCE)
  set(USE_VALIDATION_PARSER OFF CACHE BOOL "" FORCE)

  FetchContent_Declare(
    msix_sdk
    GIT_REPOSITORY ${REPACKAGER_MSIX_SDK_GIT_REPOSITORY}
    GIT_TAG        ${REPACKAGER_MSIX_SDK_GIT_TAG}
    GIT_SHALLOW    TRUE
  )

  FetchContent_GetProperties(msix_sdk)
  if(NOT msix_sdk_POPULATED)
    message(STATUS "Repackager: fetching pinned MSIX SDK ${REPACKAGER_MSIX_SDK_GIT_TAG}")
    FetchContent_Populate(msix_sdk)
    # The upstream CMake is host-specific; we only need headers + the msix target if present.
    if(EXISTS "${msix_sdk_SOURCE_DIR}/CMakeLists.txt")
      add_subdirectory(${msix_sdk_SOURCE_DIR} ${msix_sdk_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
  endif()

  if(TARGET msix)
    add_library(repackager_msix_sdk INTERFACE)
    target_link_libraries(repackager_msix_sdk INTERFACE msix)
    target_compile_definitions(repackager_msix_sdk INTERFACE REPACKAGER_HAVE_MSIX_SDK=1)
  else()
    message(WARNING "Repackager: MSIX SDK sources fetched but target 'msix' was not created")
  endif()
endfunction()
