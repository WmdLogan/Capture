# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.16

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

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "D:\Program Files\JetBrains\CLion 2019.2.1\bin\cmake\win\bin\cmake.exe"

# The command to remove a file.
RM = "D:\Program Files\JetBrains\CLion 2019.2.1\bin\cmake\win\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = D:\CLionProjects\Capture

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = D:\CLionProjects\Capture\cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/filesort.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/filesort.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/filesort.dir/flags.make

CMakeFiles/filesort.dir/file_sort.c.obj: CMakeFiles/filesort.dir/flags.make
CMakeFiles/filesort.dir/file_sort.c.obj: CMakeFiles/filesort.dir/includes_C.rsp
CMakeFiles/filesort.dir/file_sort.c.obj: ../file_sort.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/filesort.dir/file_sort.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\filesort.dir\file_sort.c.obj   -c D:\CLionProjects\Capture\file_sort.c

CMakeFiles/filesort.dir/file_sort.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/filesort.dir/file_sort.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\file_sort.c > CMakeFiles\filesort.dir\file_sort.c.i

CMakeFiles/filesort.dir/file_sort.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/filesort.dir/file_sort.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\file_sort.c -o CMakeFiles\filesort.dir\file_sort.c.s

# Object files for target filesort
filesort_OBJECTS = \
"CMakeFiles/filesort.dir/file_sort.c.obj"

# External object files for target filesort
filesort_EXTERNAL_OBJECTS =

filesort.exe: CMakeFiles/filesort.dir/file_sort.c.obj
filesort.exe: CMakeFiles/filesort.dir/build.make
filesort.exe: CMakeFiles/filesort.dir/linklibs.rsp
filesort.exe: CMakeFiles/filesort.dir/objects1.rsp
filesort.exe: CMakeFiles/filesort.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable filesort.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\filesort.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/filesort.dir/build: filesort.exe

.PHONY : CMakeFiles/filesort.dir/build

CMakeFiles/filesort.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\filesort.dir\cmake_clean.cmake
.PHONY : CMakeFiles/filesort.dir/clean

CMakeFiles/filesort.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" D:\CLionProjects\Capture D:\CLionProjects\Capture D:\CLionProjects\Capture\cmake-build-debug D:\CLionProjects\Capture\cmake-build-debug D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles\filesort.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/filesort.dir/depend

