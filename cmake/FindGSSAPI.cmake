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
set(_HEIMDAL_MODNAME heimdal-gssapi)
#set(_HEIMDAL_MODNAME heimdal-gssapi heimdal-krb5)
#set(_HEIMDAL_MODNAME heimdal-gssapi heimdal-krb5 krb5 krb5-gssapi kafs)
#set(_HEIMDAL_MODNAME heimdal-krb5)
#set(_HEIMDAL_MODNAME heimdal-kadm-server)

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckTypeSize)

message(STATUS "ENV{GSS_ROOT_FLAVOUR}=$ENV{GSS_ROOT_FLAVOUR} ; GSS_ROOT_DIR=$ENV{GSS_ROOT_DIR}")

# export GSS_ROOT_DIR and GSS_ROOT_FLAVOUR to use pkg-config system under UNIX to tell 
# which module to check (mit-krb5-gssapi or heimdal-gssapi).
if(UNIX)
  if(NOT "$ENV{GSS_ROOT_DIR} " STREQUAL " " OR NOT "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
    if("$ENV{GSS_ROOT_DIR} " STREQUAL " " OR "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
      message(WARNING "Please export GSS_ROOT_DIR ($ENV{GSS_ROOT_DIR}) AND GSS_ROOT_FLAVOUR ($ENV{GSS_ROOT_FLAVOUR}) (MIT or Heimdal) to use pkg-config system")
    else()
      if("$ENV{GSS_ROOT_FLAVOUR}" STREQUAL "MIT" OR "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
        message(STATUS "vendor MIT")
        set(GSS_FLAVOUR "MIT")
      else()
        message(STATUS "vendor Heimdal")
        set(GSS_FLAVOUR "Heimdal")
      endif()
    endif()
  else()
    message(STATUS "on est dans le else de test gssrootdir/flavour vide")
  endif()
endif()

set(_GSS_ROOT_HINTS
    "${GSS_ROOT_DIR}"
    "$ENV{GSS_ROOT_DIR}"
)


#if(NOT "$ENV{GSS_ROOT_DIR} " STREQUAL " "
message(STATUS "_GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}")
message(STATUS "ENV{GSS_ROOT_DIR}=$ENV{GSS_ROOT_DIR}")

set(vendor "`which krb5-config` --vendor")
message(STATUS "vendor=${vendor}") 

# try to find library using system pkg-config if user didn't specify root dir
if(UNIX)
  if(NOT "$ENV{GSS_ROOT_DIR} " STREQUAL " " AND NOT "$ENV{GSS_ROOT_FLAVOUR} " STREQUAL " ")
    message(STATUS "ENV GSS ROOT FLAVOUR is set")
    find_package(PkgConfig QUIET)
    if($ENV{GSS_ROOT_FLAVOUR} STREQUAL "MIT")
      message(STATUS "pkg mit flavour")
      pkg_search_module(_GSS_PKG ${_MIT_MODNAME})
    else()
      message(STATUS "pkg heimdal flavour")
      pkg_search_module(_GSS_PKG ${_HEIMDAL_MODNAME})
    endif()
    list(APPEND _GSS_ROOT_HINTS "${_GSS_PKG_PREFIX}")
    message(STATUS "_GSS_PKG_PREFIX=${_GSS_PKG_PREFIX} ; _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS}")
  endif()
elseif(WIN32)
  list(APPEND _GSS_ROOT_HINTS "[HKEY_LOCAL_MACHINE\\SOFTWARE\\MIT\\Kerberos;InstallDir]")
endif()

#message(WARNING "l.40 : _GSS_ROOT_HINTS=${_GSS_ROOT_HINTS} ; GSS_FLAVOUR=${GSS_FLAVOUR}")

if(NOT _GSS_FOUND) #not found by pkg-config. Let's take more traditional approach.
#	message(WARNING "on est la : l.41")
    #find_file(_GSS_CONFIGURE_SCRIPT
    find_file(${_GSS_CONFIGURE_SCRIPT}
        NAMES
            "krb5-config"
        HINTS
            ${_GSS_ROOT_HINTS}  #`which krb5-config` --prefix  #${_GSS_ROOT_HINTS}
        PATH_SUFFIXES
            bin
        NO_CMAKE_PATH
        NO_CMAKE_ENVIRONMENT_PATH
    )

	#message(WARNING "on est la : l.53 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT} ; HINTS=${HINTS} ; bin=${bin}")
    # if not found in user-supplied directories, maybe system knows better
    #find_file(_GSS_CONFIGURE_SCRIPT
    find_file(${_GSS_CONFIGURE_SCRIPT}
        NAMES
            "krb5-config"
        PATH_SUFFIXES
            bin
    )

    if(_GSS_CONFIGURE_SCRIPT)
	message(STATUS "on est la : l.108 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")
        execute_process(
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "gssapi" "krb5" "kafs" "kadm-server"
#            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "heimdal-gssapi"
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "kafs"
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--cflags" "krb5"
            OUTPUT_VARIABLE _GSS_CFLAGS
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )
#        execute_process(
 #           COMMAND ${_GSS_CONFIGURE_SCRIPT} "--deps"
  #          OUTPUT_VARIABLE _GSS_CFLAGS
  #          RESULT_VARIABLE _GSS_CONFIGURE_FAILED
  #      )


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

	message(STATUS "on est la : l.132 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")
        execute_process(
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi"
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "krb5"
            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "kafs"
            #COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "gssapi" "krb5" "kafs" "kadm-server"
#            COMMAND ${_GSS_CONFIGURE_SCRIPT} "--libs" "heimdal-gssapi"
            OUTPUT_VARIABLE _GSS_LIB_FLAGS
            RESULT_VARIABLE _GSS_CONFIGURE_FAILED
        )

	#message("avant : OUTPUT_VARIABLE=${OUTPUT_VARIABLE} ; RESULT_VARIABLE=${RESULT_VARIABLE}")
	#message("avant : _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS} ; _GSS_CONFIGURE_FAILED=${_GSS_CONFIGURE_FAILED}")
	#message("apres : OUTPUT_VARIABLE=${OUTPUT_VARIABLE} ; RESULT_VARIABLE=${RESULT_VARIABLE}")
        if(NOT _GSS_CONFIGURE_FAILED) # 0 means success
            # this script gives us libraries and link directories. Blah. We have to deal with it.
            # string(STRIP "krb5support ${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
            message(STATUS "l.148: _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS}")
	    string(STRIP "${_GSS_LIB_FLAGS}" _GSS_LIB_FLAGS)
            message(STATUS "l.150: _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS}")
            string(REGEX REPLACE " +-(L|l)" ";-\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")
            message(STATUS "l.152: _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS}")
            string(REGEX REPLACE " +-([^Ll][^ \\t;]*)" ";-\\1" _GSS_LIB_FLAGS "${_GSS_LIB_FLAGS}")
            message(STATUS "l.154: _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS}")

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
            message(STATUS "l.167: _GSS_LIB_FLAGS=${_GSS_LIB_FLAGS}")
        endif()

	message(STATUS "on est la : l.167 : _GSS_CONFIGURE_SCRIPT=${_GSS_CONFIGURE_SCRIPT}")

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
	    message(WARNING "on est la : l.157")
            set(GSS_FLAVOUR "Heimdal") # most probably, shouldn't really matter
        else()
	    message(STATUS "on est la : l.160")
            if(_GSS_VENDOR MATCHES ".*H|heimdal.*")
	        message(STATUS "on est la : l.162")
                set(GSS_FLAVOUR "Heimdal")
            else()
                set(GSS_FLAVOUR "MIT")
            endif()
        endif()

    else() # either there is no config script or we are on platform that doesn't provide one (Windows?)
	message(STATUS "on est la : l.206")

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
            message(STATUS "on est la : l.219")
            set(CMAKE_REQUIRED_INCLUDES "${_GSS_INCLUDE_DIR}")
            check_include_files( "gssapi/gssapi_generic.h;gssapi/gssapi_krb5.h" _GSS_HAVE_MIT_HEADERS)

            if(_GSS_HAVE_MIT_HEADERS)
                set(GSS_FLAVOUR "MIT")
            else()
		message(STATUS "on est la : l.226")
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
            message(STATUS "par ici : l.235")
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
		message(STATUS "on est la : l.248")
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
                    #set(_GSS_LIBNAME "krb5")
                    set(_KAFS_LIBNAME "kafs")
#                    list(APPEND _GSS_LIBNAME "kafs")
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
     
            if(${GSS_FLAVOUR} STREQUAL "Heimdal")
#                add_library(${module_name} 
		find_library(_KAFS_LIBRARY
		    NAMES
                        ${_KAFS_LIBNAME}
                    HINTS
                        ${_GSS_LIBDIR_HINTS}
                    PATH_SUFFIXES
                        ${_GSS_LIBDIR_SUFFIXES}
               )
	#	target_link_libraries(
                message(STATUS "_GSS_LIBRARIES avant append=${_GSS_LIBRARIES}")
		list(APPEND _GSS_LIBRARIES ${_KAFS_LIBRARY})
                message(STATUS "_GSS_LIBRARIES apres append=${_GSS_LIBRARIES}")
            endif()



        endif()

    endif()
else()
    message(STATUS "on est la : l.305")
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

message(STATUS "GSS_LIBRARIES=${GSS_LIBRARIES}")

find_package_handle_standard_args(GSS
    REQUIRED_VARS
        ${_GSS_REQUIRED_VARS}
    VERSION_VAR
        GSS_VERSION
    FAIL_MESSAGE
        "Could NOT find GSS, try to set the path to GSS root folder in the system variable GSS_ROOT_DIR"
)

mark_as_advanced(GSS_INCLUDE_DIR GSS_LIBRARIES)
