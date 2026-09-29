# Emit a header carrying the SHA256 of one source file.
#
# WHY THIS EXISTS. A test binary that is stale with respect to its source reports failures at line
# numbers that no longer mean anything, and the only way to notice is to infer it from those line
# numbers -- which is exactly how the W7 whole-move test's production binary was caught on
# 2026-09-17, after a mutation run rebuilt only one of the two build directories. The generated
# header is an OUTPUT of a custom command that DEPENDS on the source, so ninja regenerates it
# whenever the source changes and a stale binary becomes impossible to build silently: the binary
# prints the hash it was compiled against, and it can be compared with `sha256sum` of the file.
#
# Invoked as: cmake -DSRC=<abs source> -DHDR=<abs header> -P embed_source_id.cmake
file(SHA256 "${SRC}" SRC_SHA)
get_filename_component(SRC_NAME "${SRC}" NAME)
file(WRITE "${HDR}"
     "#pragma once\n"
     "// Generated. Do not edit; see dbt/cmake/embed_source_id.cmake.\n"
     "#define WM_SOURCE_SHA256 \"${SRC_SHA}\"\n"
     "#define WM_SOURCE_NAME \"${SRC_NAME}\"\n")
