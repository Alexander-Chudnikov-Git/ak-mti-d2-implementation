include(FetchContent)
include(ExternalProject)

include(cmake/utils/list_all_subdirectories.cmake)

message(STATUS "CXX compiler:      ${CMAKE_CXX_COMPILER_ID}")

if(NOT CMAKE_RELEASE)
	set(CMAKE_CXX_FLAGS    "${CMAKE_CXX_FLAGS} -g")
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS}")
endif()

# [INCLUDE DIRECTORIES]
set(PROJECT_INCLUDE_DIRS)

# [LIBRARIES LIST]
set(PROJECT_LIBRARIES_LIST)

# [SOURCE DIRECTORIES]
set(PROJECT_MAIN_SRC_DIR   "${CMAKE_SOURCE_DIR}/src")

file(GLOB PROJECT_MAIN_SRC_FILES
    "${PROJECT_MAIN_SRC_DIR}/*.hpp"
    "${PROJECT_MAIN_SRC_DIR}/*.cpp"
)

# [SOURCE GROUPS]
source_group("Main" FILES ${PROJECT_MAIN_SRC_FILES})

list(APPEND PROJECT_INCLUDE_DIRS ${PROJECT_MAIN_SRC_DIR})

# LINUX does not exclude MACOS, so we need to check it first
if(MACOS)
    message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
elseif(LINUX)
    include(cmake/platform/linux_builder.cmake)
else()
    message(FATAL_ERROR "Unsupported OS: ${CMAKE_SYSTEM_NAME}")
endif()

list(APPEND PROJECT_LIBRARIES_LIST pthread)

# [LIBRARIES]
include(cmake/libraries/cxxopts.cmake)
include(cmake/libraries/fmt.cmake)
include(cmake/libraries/spdlog.cmake)
include(cmake/libraries/akrypt.cmake)
include(cmake/libraries/utils.cmake)
include(cmake/libraries/mti-d2.cmake)

target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INCLUDE_DIRS})
target_link_directories(${PROJECT_NAME}    PUBLIC ${PROJECT_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME}      PRIVATE ${PROJECT_LIBRARIES_LIST})

include(cmake/utils/upx_compress.cmake)
