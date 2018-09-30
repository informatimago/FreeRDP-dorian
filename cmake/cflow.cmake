
function(add_cflow_target module)
  set(DEFS -D__extension__= -D__leaf__= -D__attribute__\\\(x\\\)= )
  set(DEFAULT_INCLUDES)
  set(AM_CPPFLAGS)
  set(CPPFLAGS)
  get_target_property(target_cflow_sources       ${module} SOURCES)
  get_target_property(target_include_directories ${module} INCLUDE_DIRECTORIES)
  string(REGEX REPLACE ";" " -I" target_cflow_includes "-I${target_include_directories}")
  # message(AUTHOR_WARNING "PJB TARGET ${module}.cflow")
  # message(AUTHOR_WARNING "PJB target_cflow_includes = ${target_cflow_includes}")
  # message(AUTHOR_WARNING "PJB target_cflow_sources  = ${target_cflow_sources}")


  add_custom_command(OUTPUT ${module}.cflow
    COMMAND echo cflow -o ${module}.cflow --emacs ${DEFS} ${DEFAULT_INCLUDES} ${target_cflow_includes} ${AM_CPPFLAGS} ${CPPFLAGS} ${target_cflow_sources}
    COMMAND cflow -o ${module}.cflow --emacs ${DEFS} ${DEFAULT_INCLUDES} ${target_cflow_includes} ${AM_CPPFLAGS} ${CPPFLAGS} ${target_cflow_sources}
    COMMENT "Computing Call Graph ${module}"
    VERBATIM)

  add_custom_target(${module}-cflow DEPENDS ${module}.cflow)

endfunction()
