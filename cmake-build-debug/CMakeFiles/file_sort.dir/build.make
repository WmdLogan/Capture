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
CMAKE_COMMAND = /home/logan/下载/clion-2020.1/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /home/logan/下载/clion-2020.1/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/logan/CLionProjects/Capture

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/logan/CLionProjects/Capture/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/file_sort.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/file_sort.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/file_sort.dir/flags.make

CMakeFiles/file_sort.dir/file_sort.c.o: CMakeFiles/file_sort.dir/flags.make
CMakeFiles/file_sort.dir/file_sort.c.o: ../file_sort.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/logan/CLionProjects/Capture/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/file_sort.dir/file_sort.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/file_sort.dir/file_sort.c.o   -c /home/logan/CLionProjects/Capture/file_sort.c

CMakeFiles/file_sort.dir/file_sort.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/file_sort.dir/file_sort.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/logan/CLionProjects/Capture/file_sort.c > CMakeFiles/file_sort.dir/file_sort.c.i

CMakeFiles/file_sort.dir/file_sort.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/file_sort.dir/file_sort.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/logan/CLionProjects/Capture/file_sort.c -o CMakeFiles/file_sort.dir/file_sort.c.s

# Object files for target file_sort
file_sort_OBJECTS = \
"CMakeFiles/file_sort.dir/file_sort.c.o"

# External object files for target file_sort
file_sort_EXTERNAL_OBJECTS =

file_sort: CMakeFiles/file_sort.dir/file_sort.c.o
file_sort: CMakeFiles/file_sort.dir/build.make
file_sort: CMakeFiles/file_sort.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/logan/CLionProjects/Capture/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable file_sort"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/file_sort.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/file_sort.dir/build: file_sort

.PHONY : CMakeFiles/file_sort.dir/build

CMakeFiles/file_sort.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/file_sort.dir/cmake_clean.cmake
.PHONY : CMakeFiles/file_sort.dir/clean

CMakeFiles/file_sort.dir/depend:
	cd /home/logan/CLionProjects/Capture/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/logan/CLionProjects/Capture /home/logan/CLionProjects/Capture /home/logan/CLionProjects/Capture/cmake-build-debug /home/logan/CLionProjects/Capture/cmake-build-debug /home/logan/CLionProjects/Capture/cmake-build-debug/CMakeFiles/file_sort.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/file_sort.dir/depend

