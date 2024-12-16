# This file will be configured to contain variables for CPack. These variables
# should be set in the CMake list file of the project before CPack module is
# included. The list of available CPACK_xxx variables and their associated
# documentation may be obtained using
#  cpack --help-variable-list
#
# Some variables are common to all generators (e.g. CPACK_PACKAGE_NAME)
# and some are specific to a generator
# (e.g. CPACK_NSIS_EXTRA_INSTALL_COMMANDS). The generator specific variables
# usually begin with CPACK_<GENNAME>_xxxx.


set(CPACK_BUILD_SOURCE_DIRS "/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation;/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation/build")
set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_COMPONENT_UNSPECIFIED_HIDDEN "TRUE")
set(CPACK_COMPONENT_UNSPECIFIED_REQUIRED "TRUE")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libbz2-1.0, libelf1")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://libakrypt.ru")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Axel Kenzo <axelkenzo@mail.ru>")
set(CPACK_DEFAULT_PACKAGE_DESCRIPTION_FILE "/usr/share/cmake/Templates/CPack.GenericDescription.txt")
set(CPACK_DEFAULT_PACKAGE_DESCRIPTION_SUMMARY "ak-mti-d2-utility built using CMake")
set(CPACK_GENERATOR "DEB")
set(CPACK_INNOSETUP_ARCHITECTURE "x64")
set(CPACK_INSTALL_CMAKE_PROJECTS "/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation/build;ak-mti-d2-utility;ALL;/")
set(CPACK_INSTALL_PREFIX "/usr/local")
set(CPACK_MODULE_PATH "/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation/build/_deps/libakrypt-src/cmake")
set(CPACK_NSIS_DISPLAY_NAME "ak-mti-d2-utility 0.9.16")
set(CPACK_NSIS_INSTALLER_ICON_CODE "")
set(CPACK_NSIS_INSTALLER_MUI_ICON_CODE "")
set(CPACK_NSIS_INSTALL_ROOT "\$PROGRAMFILES")
set(CPACK_NSIS_PACKAGE_NAME "ak-mti-d2-utility 0.9.16")
set(CPACK_NSIS_UNINSTALL_NAME "Uninstall")
set(CPACK_OBJCOPY_EXECUTABLE "/sbin/objcopy")
set(CPACK_OBJDUMP_EXECUTABLE "/sbin/objdump")
set(CPACK_OUTPUT_CONFIG_FILE "/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation/build/CPackConfig.cmake")
set(CPACK_PACKAGE_DEFAULT_LOCATION "/")
set(CPACK_PACKAGE_DESCRIPTION "Библиотека, реализующая российские криптографические механизмы в пространстве пользователя")
set(CPACK_PACKAGE_DESCRIPTION_FILE "/usr/share/cmake/Templates/CPack.GenericDescription.txt")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ak-mti-d2-utility built using CMake")
set(CPACK_PACKAGE_FILE_NAME "ak-mti-d2-utility-0.9.16-x86_64")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "ak-mti-d2-utility 0.9.16")
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "ak-mti-d2-utility 0.9.16")
set(CPACK_PACKAGE_NAME "ak-mti-d2-utility")
set(CPACK_PACKAGE_RELOCATABLE "true")
set(CPACK_PACKAGE_VENDOR "Axel Kenzo и Московский институт электроники и математики")
set(CPACK_PACKAGE_VERSION "0.9.16")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "9")
set(CPACK_PACKAGE_VERSION_PATCH "16")
set(CPACK_READELF_EXECUTABLE "/sbin/readelf")
set(CPACK_RESOURCE_FILE_LICENSE "/usr/share/cmake/Templates/CPack.GenericLicense.txt")
set(CPACK_RESOURCE_FILE_README "/usr/share/cmake/Templates/CPack.GenericDescription.txt")
set(CPACK_RESOURCE_FILE_WELCOME "/usr/share/cmake/Templates/CPack.GenericWelcome.txt")
set(CPACK_SET_DESTDIR "OFF")
set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_IGNORE_FILES "\\.git/;.gitignore;.delme*;.kdev4/*;TAGS;CMakeLists.txt.user*;scratch*")
set(CPACK_SOURCE_OUTPUT_CONFIG_FILE "/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation/build/CPackSourceConfig.cmake")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "ak-mti-d2-utility-0.9.16")
set(CPACK_STRIP_FILES "TRUE")
set(CPACK_SYSTEM_NAME "Linux")
set(CPACK_THREADS "1")
set(CPACK_TOPLEVEL_TAG "Linux")
set(CPACK_VERBATIM_VARIABLES "YES")
set(CPACK_WIX_SIZEOF_VOID_P "8")

if(NOT CPACK_PROPERTIES_FILE)
  set(CPACK_PROPERTIES_FILE "/home/chooisfox/Documents/programming/cpp/blueline-software/ak-mti-d2-implementation/build/CPackProperties.cmake")
endif()

if(EXISTS ${CPACK_PROPERTIES_FILE})
  include(${CPACK_PROPERTIES_FILE})
endif()
