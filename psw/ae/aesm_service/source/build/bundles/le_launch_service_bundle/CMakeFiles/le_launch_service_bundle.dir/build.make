# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build

# Include any dependencies generated for this target.
include bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/depend.make

# Include the progress variables for this target.
include bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/progress.make

# Include the compile flags for this target's objects.
include bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/flags.make

bundles/le_launch_service_bundle/launch_enclave_u.c:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating launch_enclave_u.c"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle && /opt/intel/sgxsdk/bin/x64/sgx_edger8r --untrusted --untrusted-dir /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/../../le/launch_enclave.edl --search-path /opt/intel/sgxsdk/include

bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp: bundles/le_launch_service_bundle/le_launch_service_bundle/res_0.zip
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Checking resource dependencies for le_launch_service_bundle"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/cmake -E copy /home/lcy/workspace/linux-sgx/external/CppMicroServices/local-install/share/cppmicroservices4/cmake/CMakeResourceDependencies.cpp /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp

bundles/le_launch_service_bundle/le_launch_service_bundle/res_0.zip: ../bundles/le_launch_service_bundle/manifest.json
bundles/le_launch_service_bundle/le_launch_service_bundle/res_0.zip: /home/lcy/workspace/linux-sgx/external/CppMicroServices/local-install/bin/usResourceCompiler4
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Checking resource dependencies for le_launch_service_bundle"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle && /usr/bin/cmake -E make_directory /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle && /home/lcy/workspace/linux-sgx/external/CppMicroServices/local-install/bin/usResourceCompiler4 -o /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/res_0.zip -n le_launch_service_bundle_name -r manifest.json

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.o: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/flags.make
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.o: ../bundles/le_launch_service_bundle/LEClass.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.o"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.o -c /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle/LEClass.cpp

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.i"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle/LEClass.cpp > CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.i

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.s"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle/LEClass.cpp -o CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.s

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.o: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/flags.make
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.o: ../bundles/le_launch_service_bundle/le_launch_service_bundle.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.o"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.o -c /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle/le_launch_service_bundle.cpp

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.i"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle/le_launch_service_bundle.cpp > CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.i

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.s"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle/le_launch_service_bundle.cpp -o CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.s

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.o: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/flags.make
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.o: bundles/le_launch_service_bundle/launch_enclave_u.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.o"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.o   -c /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/launch_enclave_u.c

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.i"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/launch_enclave_u.c > CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.i

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.s"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/launch_enclave_u.c -o CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.s

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.o: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/flags.make
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.o: bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.o"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.o -c /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.i"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp > CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.i

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.s"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp -o CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.s

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.o: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/flags.make
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.o: bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_init.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.o"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.o -c /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_init.cpp

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.i"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_init.cpp > CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.i

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.s"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_init.cpp -o CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.s

# Object files for target le_launch_service_bundle
le_launch_service_bundle_OBJECTS = \
"CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.o" \
"CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.o" \
"CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.o" \
"CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.o" \
"CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.o"

# External object files for target le_launch_service_bundle
le_launch_service_bundle_EXTERNAL_OBJECTS =

bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/LEClass.cpp.o
bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle.cpp.o
bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/launch_enclave_u.c.o
bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_resources.cpp.o
bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/le_launch_service_bundle/cppmicroservices_init.cpp.o
bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/build.make
bin/bundles/lible_launch_service_bundle.so: /home/lcy/workspace/linux-sgx/external/CppMicroServices/local-install/lib/libCppMicroServices.so.4.0.0
bin/bundles/lible_launch_service_bundle.so: bin/libutils.so
bin/bundles/lible_launch_service_bundle.so: bin/liboal.so
bin/bundles/lible_launch_service_bundle.so: /usr/lib/x86_64-linux-gnu/libssl.so
bin/bundles/lible_launch_service_bundle.so: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/bundles/lible_launch_service_bundle.so: ../../../../../external/rdrand/src/librdrand.a
bin/bundles/lible_launch_service_bundle.so: bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX shared library ../../bin/bundles/lible_launch_service_bundle.so"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/le_launch_service_bundle.dir/link.txt --verbose=$(VERBOSE)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold "Appending zipped resources to le_launch_service_bundle"
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle && objcopy --add-section .note.sgx.aesm_resource=/home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/le_launch_service_bundle/res_0.zip /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bin/bundles/lible_launch_service_bundle.so

# Rule to build all files generated by this target.
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/build: bin/bundles/lible_launch_service_bundle.so

.PHONY : bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/build

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/clean:
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle && $(CMAKE_COMMAND) -P CMakeFiles/le_launch_service_bundle.dir/cmake_clean.cmake
.PHONY : bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/clean

bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/depend: bundles/le_launch_service_bundle/launch_enclave_u.c
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/depend: bundles/le_launch_service_bundle/le_launch_service_bundle/cppmicroservices_resources.cpp
bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/depend: bundles/le_launch_service_bundle/le_launch_service_bundle/res_0.zip
	cd /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/bundles/le_launch_service_bundle /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle /home/lcy/workspace/linux-sgx/psw/ae/aesm_service/source/build/bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : bundles/le_launch_service_bundle/CMakeFiles/le_launch_service_bundle.dir/depend

