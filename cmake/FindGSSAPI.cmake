# - Try to find the GSS Kerberos library
# Once done this will define
#
#  GSS_ROOT_DIR - Set this variable to the root installation of GSS
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
#set(_HEIMDAL_MODNAME heimdal-gssapi)
set(_HEIMDAL_MODNAME heimdal-krb5)

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckTypeSize)

#message(WARNING "GSS_ROOT_DIR=${GSS_ROOT_DIR} ; GSS_ROOT_DIR=$ENV{GSS_ROOT_DIR}")

# set root dir if not specified to avoid using pkg-config system under UNIX
# pkg-config system meets trouble when trying to find library not when others ones 
# are also installed in /usr/local. Typically, if MIT flavour is installed in /usr/local
# and Heimdal in /usr/local/heimdal, pkg-config system fails to detect Heimdal flavour.
# That's why, we need first of all to set GSS_ROOT_DIR to avoid any potential problems 
# if we have two Kerberos flavours installed on the filesystem.
if(UNIX)
  if("$ENV{GSS_ROOT_DIR} " STREQUAL " ")
    set(GSS_ROOT_DIR "`which krb5-config` --prefix")
    message(WARNING "GSS_ROOT_DIR=${GSS_ROOT_DIR}")
  else()
    string(REGEX MATCH "[H|h]eimdal" check_heimdal "$ENV{GSS_ROOT_DIR}")
    message(WARNING "check_heimdal=${check_heimdal}; GSS_ROOT_DIR=${GSS_ROOT_DIR} ; ENV{GSS_ROOT_DIR}=$ENV{GSS_ROOT_DIR}")
    if("${check_heimdal} " STREQUAL " ")
      if("$ENV{GSS_ROOT_FLAVOUR}" STREQUAL "MIT" OR "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
        message(WARNING "vendor MIT")
        set(GSS_FLAVOUR "MIT")
      endif()
    else()
      message(WARNING "vendor Heimdal")
      set(GSS_FLAVOUR "Heimdal")
    endif()
  endif()
endif()

set(_GSS_ROOT_HINTS
    "${GSS_ROOT_DIR}"
    "$ENV{GSS_ROOT_DIR}"
)

message(WARNING "_GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}")
message(WARNING "ENV{GSS_ROOT_DIR}=$ENV{GSS_ROOT_DIR}")

set(vendor "`which krb5-config` --vendor")
message(WARNING "vendor=${vendor}") 

# try to find library using system pkg-config if user didn't specify root dir
#if(NOT GSS_ROOT_DIR AND NOT "$ENV{GSS_ROOT_DIR}")
    if(UNIX)
	message(WARNING "NOT GSS ROOT DIR & NOT ENV GSS ROOT DIR")
        find_package(PkgConfig QUIET)
#        pkg_search_module(_GSS_PKG ${_MIT_MODNAME} ${_HEIMDAL_MODNAME})
	if(GSS_FLAVOUR STREQUAL "MIT")
          message(WARNING "pkg mit flavour")
          pkg_search_module(_GSS_PKG ${_MIT_MODNAME})
	else()
          message(WARNING "pkg heimdal flavour")
          pkg_search_module(_GSS_PKG ${_HEIMDAL_MODNAME})
        endif()
        list(APPEND _GSS_ROOT_HINTS "${_GSS_PKG_PREFIX}")
	message(WARNING "_GSS_PKG_PREFIX=${_GSS_PKG_PREFIX} ; _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}")
    elseif(WIN32)
        list(APPEND _GSS_ROOT_HINTS "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos;InstallDir]")
    endif()
#endif()

#message(WARNING "l.40 : _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS} ; GSS_FLAVOUR=${GSS_FLAVOUR}")

if(NOT _GSS_FOUND) #not found by pkg-config. Let's take more traditional approach.
#	message(WARNING "on est la : l.41")
    find_file(_GSS_CONFIGURE_SCRIPT
        NAMES
            "krb5-config"
        HINTS
            ${_GSS_ROOT_HINTS}  #`which krb5-config` --prefix  #${_GSS_ROOT_HINTS}
        PATH_SUFFIXES
            bin #heimdal/bin #bin
        NO_CMAKE_PATH
        NO_CMAKE_ENVIRONMENT_PATH
    )

	#message(WARNING "on est la : l.53 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT} ; HINTS=${HINTS} ; bin=${bin}")
    # if not found in user-supplied directories, maybe system knows better
    find_file(_GSS_CONFIGURE_SCRIPT
        NAMES
            "krb5-config"
        PATH_SUFFIXES
            bin
    )

    if(_GSS_CONFIGURE_SCRIPT)
	#message(WARNING "on est la : l.63")
        execute_process(
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "gssapi"
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "krb5"
            OUTPUT_VARIABLE _GSS_CFLAGS
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )
	#message(WARNING "on est la : l.68")
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

	#message(WARNING "on est la : l.85")
        execute_process(
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi"
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi" "krb5"
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "krb5"
            OUTPUT_VARIABLE _GSS_LIB_FLAGS
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )
	#message("avant : OUTPUT_VARIABLE=${OUTPUT_VARIABLE} ; RESULT_VARIABLE=${RESULT_VARIABLE}")
	#message("avant : _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS} ; _GSS_CONFIGURE_FAILED=${_GSS_CONFIGURE_FAILED}")
#        execute_process(
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi"
#            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "krb5"
 #           OUTPUT_VARIABLE _GSS_LIB_FLAGS
 #           RESULT_VARIABLE _GSS_CONFIGURE_FAILED
 #       )
	#message("apres : OUTPUT_VARIABLE=${OUTPUT_VARIABLE} ; RESULT_VARIABLE=${RESULT_VARIABLE}")
        if(NOT _GSS_CONFIGURE_FAILED) # 0 means success
            # this script gives us libraries and link directories. Blah. We have to deal with it.
            # string(STRIP "krb5support ${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
			string(STRIP "${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
            string(REGEX REPLACE " +-(L|l)" ";-\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")
            string(REGEX REPLACE " +-([^Ll][^ \\t;]*)" ";-\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")

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
        endif()

	#message(WARNING "on est la : l.112 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")

        execute_process(
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--version"
            OUTPUT_VARIABLE _GSS_VERSION
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )

        # older versions may not have the "--version" parameter. In this case we just don't care.
        if(_GSS_CONFIGURE_FAILED)
            set(_GSS_VERSION 0)
        endif()


        execute_process(
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--vendor"
            OUTPUT_VARIABLE _GSS_VENDOR
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )
	#message(WARNING "on est la : l.153")

        # older versions may not have the "--vendor" parameter. In this case we just don't care.
        if(_GSS_CONFIGURE_FAILED)
	#message(WARNING "on est la : l.157")
            set(GSS_FLAVOUR "Heimdal") # most probably, shouldn't really matter
        else()
	#message(WARNING "on est la : l.160")
            if(_GSS_VENDOR MATCHES ".*H|heimdal.*")
	#message(WARNING "on est la : l.162")
                set(GSS_FLAVOUR "Heimdal")
            else()
                set(GSS_FLAVOUR "MIT")
            endif()
        endif()

    else() # either there is no config script or we are on platform that doesn't provide one (Windows?)
	#message(WARNING "on est la : l.142")

        find_path(_GSS_INCLUDE_DIR
            NAMES
                "gssapi/gssapi.h"
            HINTS
                ${_GSS_ROOT_HINTS}
            PATH_SUFFIXES
                include
                inc
        )

        if(_GSS_INCLUDE_DIR) #jay, we've found something
	#message(WARNING "on est la : l.180")
            set(CMAKE_REQUIRED_INCLUDES "${_GSS_INCLUDE_DIR}")
            check_include_files( "gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" _GSS_HAVE_MIT_HEADERS)

            if(_GSS_HAVE_MIT_HEADERS)
                set(GSS_FLAVOUR "MIT")
            else()
		#message(WARNING "on est la : l.190")
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
            # I'm not convinced if this is the right way but this is what autotools do at the moment
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
		#message(WARNING "on est la : l.211")
                set(GSS_FLAVOUR "Heimdal")
            endif()
        endif()

        # if we have headers, check if we can link libraries
        if(GSS_FLAVOUR)
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
                message(STATUS "avant append libdir suffixes")
                list(APPEND _GSS_LIBDIR_SUFFIXES "lib;lib64") # those suffixes are not checked for HINTS
                if(GSS_FLAVOUR STREQUAL "MIT")
		    message(STATUS "on est la : l.278")
                    set(_GSS_LIBNAME "gssapi_krb5")
                else()
		    message(STATUS "on est la : l.281")
                    set(_GSS_LIBNAME "gssapi")
                    set(_GSS_LIBNAME "krb5")
                    set(_GSS_LIBNAME "kafs")
                endif()
            endif()

            message(STATUS "l.289: _GSS_LIBNAME=${_GSS_LIBNAME}; _GSS_LIBDIR_HINTS=${_GSS_LIBDIR_HINTS}; _GSS_LIBDIR_SUFFIXES=${_GSS_LIBDIR_SUFFIXES}")

            find_library(_GSS_LIBRARIES
                NAMES
                    ${_GSS_LIBNAME}
                HINTS
                    ${_GSS_LIBDIR_HINTS}
                PATH_SUFFIXES
                    ${_GSS_LIBDIR_SUFFIXES}
            )

        endif()

    endif()
else()
	#message(WARNING "on est la : l.235")
    if(_GSS_PKG_${_MIT_MODNAME}_VERSION)
        set(GSS_FLAVOUR "MIT")
        set(_GSS_VERSION _GSS_PKG_${_MIT_MODNAME}_VERSION)
    else()
	#message(WARNING "on est la : l.240")
        set(GSS_FLAVOUR "Heimdal")
        set(_GSS_VERSION _GSS_PKG_${_HEIMDAL_MODNAME}_VERSION)
    endif()
endif()
	
message(STATUS "l.314: _GSS_LIBRARIES=${_GSS_LIBRARIES}")

set(GSS_INCLUDE_DIR ${_GSS_INCLUDE_DIR})
set(GSS_LIBRARIES ${_GSS_LIBRARIES})
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

message(WARNING "GSS_LIBRARIES=${GSS_LIBRARIES}")

find_package_handle_standard_args(GSS
    REQUIRED_VARS
        ${_GSS_REQUIRED_VARS}
    VERSION_VAR
        GSS_VERSION
    FAIL_MESSAGE
        "Could NOT find GSS, try to set the path to GSS root folder in the system variable GSS_ROOT_DIR"
)

mark_as_advanced(GSS_INCLUDE_DIR GSS_LIBRARIES)
