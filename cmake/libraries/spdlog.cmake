set(CURRENT_LIBRARY_NAME spdlog)

FetchContent_Declare(
  ${CURRENT_LIBRARY_NAME}
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.15.0
)

FetchContent_MakeAvailable(${CURRENT_LIBRARY_NAME})

list(APPEND PROJECT_LIBRARIES_LIST spdlog::spdlog)

target_compile_definitions(${PROJECT_NAME} PRIVATE SPDLOG_ENABLE_SYSLOG)

