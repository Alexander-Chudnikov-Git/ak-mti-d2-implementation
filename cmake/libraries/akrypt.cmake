FetchContent_Declare(
  libakrypt
  GIT_REPOSITORY https://git.miem.hse.ru/axelkenzo/libakrypt-0.x.git
  GIT_TAG        0.9.16
)
FetchContent_MakeAvailable(libakrypt)

list(APPEND PROJECT_LIBRARIES_LIST libakrypt-base.so libakrypt.so)
