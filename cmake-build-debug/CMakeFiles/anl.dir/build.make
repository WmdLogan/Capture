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
include CMakeFiles/anl.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/anl.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/anl.dir/flags.make

CMakeFiles/anl.dir/analysis.c.obj: CMakeFiles/anl.dir/flags.make
CMakeFiles/anl.dir/analysis.c.obj: CMakeFiles/anl.dir/includes_C.rsp
CMakeFiles/anl.dir/analysis.c.obj: ../analysis.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/anl.dir/analysis.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\anl.dir\analysis.c.obj   -c D:\CLionProjects\Capture\analysis.c

CMakeFiles/anl.dir/analysis.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/anl.dir/analysis.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\analysis.c > CMakeFiles\anl.dir\analysis.c.i

CMakeFiles/anl.dir/analysis.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/anl.dir/analysis.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\analysis.c -o CMakeFiles\anl.dir\analysis.c.s

# Object files for target anl
anl_OBJECTS = \
"CMakeFiles/anl.dir/analysis.c.obj"

# External object files for target anl
anl_EXTERNAL_OBJECTS =

anl.exe: CMakeFiles/anl.dir/analysis.c.obj
anl.exe: CMakeFiles/anl.dir/build.make
anl.exe: CMakeFiles/anl.dir/linklibs.rsp
anl.exe: CMakeFiles/anl.dir/objects1.rsp
anl.exe: CMakeFiles/anl.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable anl.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\anl.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/anl.dir/build: anl.exe

.PHONY : CMakeFiles/anl.dir/build

CMakeFiles/anl.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\anl.dir\cmake_clean.cmake
.PHONY : CMakeFiles/anl.dir/clean

CMakeFiles/anl.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" D:\CLionProjects\Capture D:\CLionProjects\Capture D:\CLionProjects\Capture\cmake-build-debug D:\CLionProjects\Capture\cmake-build-debug D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles\anl.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/anl.dir/depend

