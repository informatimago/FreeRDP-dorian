# - Try to find the GSS Kerberos libraries
# Once done this will define
#
#  GSS_ROOT_DIR - Set this variable to the root installation of GSS
#  GSS_ROOT_FLAVOUR - Set this variable to the flavour of Kerberos installation (MIT or Heimdal)
#
# Read-Only variables:
#  GSS_FOUND - system has the Heimdal library
#  GSS_FLAVOUR - "MIT" or "Heimdal" if anything found.
#  GSS_INCLUDE_DIR - the Heimdal include directory
#  GSS_LIBRARIES - The libraries needed to use GSS
#  GSS_LINK_DIRECTORIES - Directories to add to linker search path
#  GSS_LINKER_FLAGS - Additional linker flags
#  GSS_COMPILER_FLAGS - Additional compiler flags
#  GSS_VERSION - This is set to version advertised by pkg-config or read from manifest.
#                In case the library is found but no version info availabe it'll be set to "unknown"

set(_MIT_MODNAME mit-krb5-gssapi)
set(_HEIMDAL_MODNAME heimdal-gssapi)

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckTypeSize)

message(STATUS "ENV{GSS_ROOT_FLAVOUR}=$ENV{GSS_ROOT_FLAVOUR} ; GSS_ROOT_DIR=$ENV{GSS_ROOT_DIR}")

# export GSS_ROOT_FLAVOUR to use pkg-config system under UNIX
if(UNIX)
  if(NOT "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
      if("$ENV{GSS_ROOT_FLAVOUR}" STREQUAL "[M|m]it" OR "$ENV{GSS_ROOT_FLAVOUR}" STREQUAL "MIT")
        set(GSS_FLAVOUR "MIT")
      elseif("$ENV{GSS_ROOT_FLAVOUR}" STREQUAL "[H|h]eimdal" OR "$ENV{GSS_ROOT_FLAVOUR}" STREQUAL "HEIMDAL")
        set(GSS_FLAVOUR "Heimdal")
      endif()
    endif()
  endif()
endif()

set(_GSS_ROOT_HINTS
    "${GSS_ROOT_DIR}"
    "$ENV{GSS_ROOT_DIR}"
)

# try to find library using system pkg-config if user did not specify root dir
if(UNIX)
  if("$ENV{GSS_ROOT_DIR} " STREQUAL " ")
    if(NOT "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
      find_package(PkgConfig QUIET)
      message(STATUS "l.65: _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; _GSS_PKG_PREFIX=${_GSS_PKG_PREFIX}")

      if(GSS_FLAVOUR STREQUAL "MIT")
        pkg_search_module(_GSS_PKG ${_MIT_MODNAME})
        message(STATUS "l.69: _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; _GSS_PKG_PREFIX=${_GSS_PKG_PREFIX}")
      else()
        pkg_search_module(_GSS_PKG ${_HEIMDAL_MODNAME})
        message(STATUS "_GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; _GSS_PKG_PREFIX=${_GSS_PKG_PREFIX}")
        #message(STATUS "l.72: _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; ENV{PKG_CONFIG_PATH}=$ENV{PKG_CONFIG_PATH}")
        #list(APPEND _GSS_ROOT_HINTS "$ENV{PKG_CONFIG_PATH}")
        #message(STATUS "l.73: _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; _GSS_PKG_PREFIX=${_GSS_PKG_PREFIX}")
      endif()
    
      if("${_GSS_PKG_PREFIX} " STREQUAL " ")
        if(NOT "$ENV{PKG_CONFIG_PATH} " STREQUAL " ")
          message(STATUS "l.72: _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; ENV{PKG_CONFIG_PATH}=$ENV{PKG_CONFIG_PATH}")
          list(APPEND _GSS_ROOT_HINTS "$ENV{PKG_CONFIG_PATH}")
          message(STATUS "l.73: _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; _GSS_PKG_PREFIX=${_GSS_PKG_PREFIX}")
        else()
          message(SEND_ERROR "Please export PKG_CONFIG_PATH=PREFIX_INSTALL_KERBEROS/lib/pkgconfig")
        endif()
      else()
        list(APPEND _GSS_ROOT_HINTS "${_GSS_PKG_PREFIX}")
        message(STATUS "_GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}; _GSS_PKG_PREFIX=${_GSS_PKG_PREFIX}")
      endif()
    else()
      message(WARNING "Please export GSS_ROOT_FLAVOUR to use pkg-config")
    endif()
  endif()
elseif(WIN32)
  list(APPEND _GSS_ROOT_HINTS "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos;InstallDir]")
endif()

if(NOT _GSS_FOUND) # not found by pkg-config. Let's take more traditional approach.
    find_file(_GSS_CONFIGURE_SCRIPT
        NAMES
            "krb5-config"
        HINTS
            ${_GSS_ROOT_HINTS}
        PATH_SUFFIXES
            bin
        NO_CMAKE_PATH
        NO_CMAKE_ENVIRONMENT_PATH
    )

    # if not found in user-supplied directories, maybe system knows better
    find_file(_GSS_CONFIGURE_SCRIPT
        NAMES
            "krb5-config"
        PATH_SUFFIXES
            bin
    )
	
    message(STATUS "on est la avant gss script : l.85 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")

    if(NOT GSS_FLAVOUR)
      execute_process(
           COMMAND ${_GSS_CONFIGURE_SCRIPT} "--vendor"
           OUTPUT_VARIABLE _GSS_VENDOR
           RESULT_VARIABLE _GSS_CONFIGURE_FAILED
      )

      if(_GSS_CONFIGURE_FAILED)
        set(GSS_FLAVOUR "Heimdal") # most probably, shouldn't really matter
      else()
        if(_GSS_VENDOR MATCHES ".*H|heimdal.*")
          set(GSS_FLAVOUR "Heimdal")
        else()
          set(GSS_FLAVOUR "MIT")
        endif()
      endif()
    else()
      message(STATUS "flavour already set") 
    endif()

    message(STATUS "on est apres vendor : l.106 : GSS_FLAVOUR=${GSS_FLAVOUR} ; _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")

    # FIXME : fail to link Heimdal libraries using configure script, script do it "manually"
    if(NOT "${_GSS_CONFIGURE_SCRIPT} " STREQUAL " " AND NOT ${GSS_FLAVOUR} STREQUAL "Heimdal")
      message(STATUS "on est la : l.108 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")

      if(NOT ${GSS_FLAVOUR} STREQUAL "Heimdal")
        message(STATUS "on est la : l.125 : MIT gssapi")
        execute_process(
          COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "gssapi"
          OUTPUT_VARIABLE _GSS_CFLAGS
          RESULT_VARIABLE _GSS_CONFIGURE_FAILED
       )
        message(STATUS "_GSS_CFLAGS=${_GSS_CFLAGS}")
     else()
        message(STATUS "on est la : l.132 : Heimdal gssapi")
       execute_process(
         COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "gssapi"
         OUTPUT_VARIABLE _GSS_CFLAGS
         RESULT_VARIABLE _GSS_CONFIGURE_FAILED
       )
        message(STATUS "_GSS_CFLAGS=${_GSS_CFLAGS}")
     endif() 
        
      if(NOT _GSS_CONFIGURE_FAILED) # 0 means success
            # should also work in an odd case when multiple directories are given
            string(STRIP "${_GSS_CFLAGS}" _GSS_CFLAGS)
            string(REGEX REPLACE " +-I" ";" _GSS_CFLAGS "${_GSS_CFLAGS}")
            string(REGEX REPLACE " +-([^I][^ \\t;]*)" ";-\\1" _GSS_CFLAGS "${_GSS_CFLAGS}")

            foreach(_flag ${_GSS_CFLAGS})
                if(_flag MATCHES "^-I.*")
                    string(REGEX REPLACE "^-I" "" _val "${_flag}")
                    list(APPEND _GSS_INCLUDE_DIR "${_val}")
                else()
                    list(APPEND _GSS_COMPILER_FLAGS "${_flag}")
                endif()
            endforeach()
        endif()

     if(NOT ${GSS_FLAVOUR} STREQUAL "Heimdal")
        execute_process(
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi"
            OUTPUT_VARIABLE _GSS_LIB_FLAGS
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )
        message(STATUS "_GSS_LIB_FLAGS=${_GSS_LIB_FLAGS}")
     else()
        message(STATUS "on est la : l.163 : Heimdal gssapi")
        execute_process(
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi"
            OUTPUT_VARIABLE _GSS_LIB_FLAGS
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )
        #message(STATUS "_GSS_LIB_FLAGS exec=${_GSS_LIB_FLAGS}")
        string(STRIP "${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
        list(APPEND _GSS_LIB_FLAGS "-lkrb5 -lkafs -lroken")
        string(STRIP "${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
        #message(STATUS "_GSS_LIB_FLAGS 0.0=${_GSS_LIB_FLAGS}")
        #string(REGEX REPLACE ";-(L|l)" " -\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")
        message(STATUS "_GSS_LIB_FLAGS 1.0=${_GSS_LIB_FLAGS}")

     endif()

        if(NOT _GSS_CONFIGURE_FAILED) # 0 means success
            # this script gives us libraries and link directories. We have to deal with it.
            message(STATUS "_GSS_LIB_FLAGS 0=${_GSS_LIB_FLAGS}")
            string(STRIP "${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
            message(STATUS "_GSS_LIB_FLAGS 1=${_GSS_LIB_FLAGS}")
            string(REGEX REPLACE " +-(L|l)" ";-\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")
            message(STATUS "_GSS_LIB_FLAGS 2=${_GSS_LIB_FLAGS}")
            string(REGEX REPLACE " +-([^Ll][^ \\t;]*)" ";-\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")
            message(STATUS "_GSS_LIB_FLAGS 3=${_GSS_LIB_FLAGS}")

            foreach(_flag ${_GSS_LIB_FLAGS})
                if(_flag MATCHES "^-l.*")
                    string(REGEX REPLACE "^-l" "" _val "${_flag}")
                    list(APPEND _GSS_LIBRARIES "${_val}")
                elseif(_flag MATCHES "^-L.*")
                    string(REGEX REPLACE "^-L" "" _val "${_flag}")
                    list(APPEND _GSS_LINK_DIRECTORIES "${_val}")
                else()
                    list(APPEND _GSS_LINKER_FLAGS "${_flag}")
                endif()
            endforeach()

	message(STATUS "_GSS_LIBRARIES ici=${_GSS_LIBRARIES}")
	message(STATUS "_GSS_LINK_DIRECTORIES ici=${_GSS_LINK_DIRECTORIES}")
	message(STATUS "_GSS_LINKER_FLAGS ici=${_GSS_LINKER_FLAGS}")

        endif()

        execute_process(
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--version"
            OUTPUT_VARIABLE _GSS_VERSION
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )

        # older versions may not have the "--version" parameter. In this case we just don't care.
        if(_GSS_CONFIGURE_FAILED)
            set(_GSS_VERSION 0)
        endif()

    else() # either there is no config script or we are on platform that doesn't provide one (Windows?)
        message(STATUS "on est la : l.171 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT} failed or Heimdal flavour")
        message(STATUS "l.224 : _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}")
        find_path(_GSS_INCLUDE_DIR
            NAMES
                "gssapi/gssapi.h"
            HINTS
                ${_GSS_ROOT_HINTS}
            PATH_SUFFIXES
                include
                inc
        )

        if(_GSS_INCLUDE_DIR) # we've found something
            set(CMAKE_REQUIRED_INCLUDES "${_GSS_INCLUDE_DIR}")
            check_include_files( "gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" _GSS_HAVE_MIT_HEADERS)

            if(_GSS_HAVE_MIT_HEADERS AND NOT GSS_FLAVOUR STREQUAL "Heimdal")
		message(STATUS "GSS_FLAVOUR l.239=${GSS_FLAVOUR}")
                set(GSS_FLAVOUR "MIT")
            else()
		message(STATUS "GSS_FLAVOUR l.242=${GSS_FLAVOUR}")
                # prevent compiling the header - just check if we can include it
                set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D__ROKEN_H__")
                check_include_file( "roken.h" _GSS_HAVE_ROKEN_H)

                check_include_file( "heimdal/roken.h" _GSS_HAVE_HEIMDAL_ROKEN_H)
                if(_GSS_HAVE_ROKEN_H OR _GSS_HAVE_HEIMDAL_ROKEN_H)
                    set(GSS_FLAVOUR "Heimdal")
                endif()
                set(CMAKE_REQUIRED_DEFINITIONS "")
            endif()
        else()
		message(STATUS "GSS_FLAVOUR l.253=${GSS_FLAVOUR}")
            # may not be the right way but this is what autotools do at the moment
            find_path(_GSS_INCLUDE_DIR
                NAMES
                    "gssapi.h"
                HINTS
                    ${_GSS_ROOT_HINTS}
                PATH_SUFFIXES
                    include
                    inc
            )

            if(_GSS_INCLUDE_DIR)
                set(GSS_FLAVOUR "Heimdal")
            endif()
        endif()

        # if we have headers, check if we can link libraries
        if(GSS_FLAVOUR)
	    message(STATUS "GSS_FLAVOUR l.272=${GSS_FLAVOUR}")
            set(_GSS_LIBDIR_SUFFIXES "")
            set(_GSS_LIBDIR_HINTS ${_GSS_ROOT_HINTS})
            get_filename_component(_GSS_CALCULATED_POTENTIAL_ROOT "${_GSS_INCLUDE_DIR}" PATH)
            list(APPEND _GSS_LIBDIR_HINTS ${_GSS_CALCULATED_POTENTIAL_ROOT})

            if(WIN32)
                if(CMAKE_SIZEOF_VOID_P EQUAL 8)
                    list(APPEND _GSS_LIBDIR_SUFFIXES "lib/AMD64")
                    if(GSS_FLAVOUR STREQUAL "MIT")
                        set(_GSS_LIBNAME "gssapi64")
                    else()
                        set(_GSS_LIBNAME "libgssapi")
                    endif()
                else()
                    list(APPEND _GSS_LIBDIR_SUFFIXES "lib/i386")
                    if(GSS_FLAVOUR STREQUAL "MIT")
                        set(_GSS_LIBNAME "gssapi32")
                    else()
                        set(_GSS_LIBNAME "libgssapi")
                    endif()
                endif()
            else()
                list(APPEND _GSS_LIBDIR_SUFFIXES "lib;lib64") # those suffixes are not checked for HINTS
                if(GSS_FLAVOUR STREQUAL "MIT")
                    set(_GSS_LIBNAME "gssapi_krb5")
                    set(_KRB5_LIBNAME "krb5")
                    set(_COMERR_LIBNAME "com_err")
                    set(_KRB5SUPPORT_LIBNAME "krb5support")
                else()
                    set(_GSS_LIBNAME "gssapi")
                    set(_KRB5_LIBNAME "krb5")
                    set(_KAFS_LIBNAME "kafs")
                    set(_ROKEN_LIBNAME "roken")
                endif()
            endif()
           
            find_library(_GSS_LIBRARIES
                NAMES
                    ${_GSS_LIBNAME}
                HINTS
                    ${_GSS_LIBDIR_HINTS}
                PATH_SUFFIXES
                    ${_GSS_LIBDIR_SUFFIXES}
            )

            if(${GSS_FLAVOUR} STREQUAL "MIT")
              message(STATUS "on ajoute les libs pour MIT")
              find_library(_KRB5_LIBRARY
                  NAMES
                      ${_KRB5_LIBNAME}
                  HINTS
                      ${_GSS_LIBDIR_HINTS}
                  PATH_SUFFIXES
                      ${_GSS_LIBDIR_SUFFIXES}
              )
              find_library(_COMERR_LIBRARY
                  NAMES
                      ${_COMERR_LIBNAME}
                  HINTS
                      ${_GSS_LIBDIR_HINTS}
                  PATH_SUFFIXES
                      ${_GSS_LIBDIR_SUFFIXES}
              )
              find_library(_KRB5SUPPORT_LIBRARY
                  NAMES
                      ${_KRB5SUPPORT_LIBNAME}
                  HINTS
                      ${_GSS_LIBDIR_HINTS}
                  PATH_SUFFIXES
                      ${_GSS_LIBDIR_SUFFIXES}
              )
             list(APPEND _GSS_LIBRARIES ${_KRB5_LIBRARY} ${_KRB5SUPPORT_LIBRARY} ${_COMERR_LIBRARY})
            endif()
     
            if(${GSS_FLAVOUR} STREQUAL "Heimdal")
                message(STATUS "on ajoute les libs pour Heimdal")
		find_library(_KRB5_LIBRARY
		    NAMES
                        ${_KRB5_LIBNAME}
                    HINTS
                        ${_GSS_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSS_LIBDIR_SUFFIXES}
                )
		find_library(_KAFS_LIBRARY
		    NAMES
                        ${_KAFS_LIBNAME}
                    HINTS
                        ${_GSS_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSS_LIBDIR_SUFFIXES}
                )
		find_library(_ROKEN_LIBRARY
		    NAMES
                        ${_ROKEN_LIBNAME}
                    HINTS
                        ${_GSS_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSS_LIBDIR_SUFFIXES}
                )
		list(APPEND _GSS_LIBRARIES ${_KRB5_LIBRARY} ${_KAFS_LIBRARY} ${_ROKEN_LIBRARY})
                message(STATUS "_GSS_LIBRARIES=${_GSS_LIBRARIES}")
            endif()
        endif()

        execute_process(
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--version"
            OUTPUT_VARIABLE _GSS_VERSION
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )

        # older versions may not have the "--version" parameter. In this case we just don't care.
        if(_GSS_CONFIGURE_FAILED)
            set(_GSS_VERSION 0)
        endif()

    endif()
else()
    if(_GSS_PKG_${_MIT_MODNAME}_VERSION)
        set(GSS_FLAVOUR "MIT")
        set(_GSS_VERSION _GSS_PKG_${_MIT_MODNAME}_VERSION)
    else()
        set(GSS_FLAVOUR "Heimdal")
        set(_GSS_VERSION _GSS_PKG_${_HEIMDAL_MODNAME}_VERSION)
    endif()
endif()
	
set(GSS_INCLUDE_DIR ${_GSS_INCLUDE_DIR})
message(STATUS "_GSS_INCLUDE_DIR=${_GSS_INCLUDE_DIR}")
set(GSS_LIBRARIES ${_GSS_LIBRARIES})
message(STATUS "GSS_LIBRARIES=${GSS_LIBRARIES}; _GSS_LIBRARIES=${_GSS_LIBRARIES}")
set(GSS_LINK_DIRECTORIES ${_GSS_LINK_DIRECTORIES})
set(GSS_LINKER_FLAGS ${_GSS_LINKER_FLAGS})
set(GSS_COMPILER_FLAGS ${_GSS_COMPILER_FLAGS})
set(GSS_VERSION ${_GSS_VERSION})

if(GSS_FLAVOUR)

    if(NOT GSS_VERSION AND GSS_FLAVOUR STREQUAL "Heimdal")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(HEIMDAL_MANIFEST_FILE "Heimdal.Application.amd64.manifest")
        else()
            set(HEIMDAL_MANIFEST_FILE "Heimdal.Application.x86.manifest")
        endif()

        if(EXISTS "${GSS_INCLUDE_DIR}/${HEIMDAL_MANIFEST_FILE}")
            file(STRINGS "${GSS_INCLUDE_DIR}/${HEIMDAL_MANIFEST_FILE}" heimdal_version_str
                 REGEX "^.*version=\"[0-9]\\.[^\"]+\".*$")

            string(REGEX MATCH "[0-9]\\.[^\"]+"
                   GSS_VERSION "${heimdal_version_str}")
        endif()

        if(NOT GSS_VERSION)
            set(GSS_VERSION "Heimdal Unknown")
        endif()
    elseif(NOT GSS_VERSION AND GSS_FLAVOUR STREQUAL "MIT")
        get_filename_component(_MIT_VERSION "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos\\SDK\\CurrentVersion;VersionString]" NAME CACHE)
        if(WIN32 AND _MIT_VERSION)
            set(GSS_VERSION "${_MIT_VERSION}")
        else()
            set(GSS_VERSION "MIT Unknown")
        endif()
    endif()
endif()


include(FindPackageHandleStandardArgs)

set(_GSS_REQUIRED_VARS GSS_LIBRARIES GSS_FLAVOUR)

find_package_handle_standard_args(GSS
    REQUIRED_VARS
        ${_GSS_REQUIRED_VARS}
    VERSION_VAR
        GSS_VERSION
    FAIL_MESSAGE
        "Could NOT find GSS, try to set the path to GSS root folder in the system variable GSS_ROOT_DIR"
)

mark_as_advanced(GSS_INCLUDE_DIR GSS_LIBRARIES)
