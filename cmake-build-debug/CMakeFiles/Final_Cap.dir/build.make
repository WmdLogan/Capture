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
include CMakeFiles/Final_Cap.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Final_Cap.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Final_Cap.dir/flags.make

CMakeFiles/Final_Cap.dir/main.c.obj: CMakeFiles/Final_Cap.dir/flags.make
CMakeFiles/Final_Cap.dir/main.c.obj: CMakeFiles/Final_Cap.dir/includes_C.rsp
CMakeFiles/Final_Cap.dir/main.c.obj: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/Final_Cap.dir/main.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\Final_Cap.dir\main.c.obj   -c D:\CLionProjects\Capture\main.c

CMakeFiles/Final_Cap.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Final_Cap.dir/main.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\main.c > CMakeFiles\Final_Cap.dir\main.c.i

CMakeFiles/Final_Cap.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Final_Cap.dir/main.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\main.c -o CMakeFiles\Final_Cap.dir\main.c.s

CMakeFiles/Final_Cap.dir/Capture.c.obj: CMakeFiles/Final_Cap.dir/flags.make
CMakeFiles/Final_Cap.dir/Capture.c.obj: CMakeFiles/Final_Cap.dir/includes_C.rsp
CMakeFiles/Final_Cap.dir/Capture.c.obj: ../Capture.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/Final_Cap.dir/Capture.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\Final_Cap.dir\Capture.c.obj   -c D:\CLionProjects\Capture\Capture.c

CMakeFiles/Final_Cap.dir/Capture.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Final_Cap.dir/Capture.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\Capture.c > CMakeFiles\Final_Cap.dir\Capture.c.i

CMakeFiles/Final_Cap.dir/Capture.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Final_Cap.dir/Capture.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\Capture.c -o CMakeFiles\Final_Cap.dir\Capture.c.s

CMakeFiles/Final_Cap.dir/Configure.c.obj: CMakeFiles/Final_Cap.dir/flags.make
CMakeFiles/Final_Cap.dir/Configure.c.obj: CMakeFiles/Final_Cap.dir/includes_C.rsp
CMakeFiles/Final_Cap.dir/Configure.c.obj: ../Configure.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/Final_Cap.dir/Configure.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\Final_Cap.dir\Configure.c.obj   -c D:\CLionProjects\Capture\Configure.c

CMakeFiles/Final_Cap.dir/Configure.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Final_Cap.dir/Configure.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\Configure.c > CMakeFiles\Final_Cap.dir\Configure.c.i

CMakeFiles/Final_Cap.dir/Configure.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Final_Cap.dir/Configure.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\Configure.c -o CMakeFiles\Final_Cap.dir\Configure.c.s

CMakeFiles/Final_Cap.dir/hash.c.obj: CMakeFiles/Final_Cap.dir/flags.make
CMakeFiles/Final_Cap.dir/hash.c.obj: CMakeFiles/Final_Cap.dir/includes_C.rsp
CMakeFiles/Final_Cap.dir/hash.c.obj: ../hash.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/Final_Cap.dir/hash.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\Final_Cap.dir\hash.c.obj   -c D:\CLionProjects\Capture\hash.c

CMakeFiles/Final_Cap.dir/hash.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Final_Cap.dir/hash.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\hash.c > CMakeFiles\Final_Cap.dir\hash.c.i

CMakeFiles/Final_Cap.dir/hash.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Final_Cap.dir/hash.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\hash.c -o CMakeFiles\Final_Cap.dir\hash.c.s

CMakeFiles/Final_Cap.dir/delete_hash.c.obj: CMakeFiles/Final_Cap.dir/flags.make
CMakeFiles/Final_Cap.dir/delete_hash.c.obj: CMakeFiles/Final_Cap.dir/includes_C.rsp
CMakeFiles/Final_Cap.dir/delete_hash.c.obj: ../delete_hash.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/Final_Cap.dir/delete_hash.c.obj"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\Final_Cap.dir\delete_hash.c.obj   -c D:\CLionProjects\Capture\delete_hash.c

CMakeFiles/Final_Cap.dir/delete_hash.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/Final_Cap.dir/delete_hash.c.i"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E D:\CLionProjects\Capture\delete_hash.c > CMakeFiles\Final_Cap.dir\delete_hash.c.i

CMakeFiles/Final_Cap.dir/delete_hash.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/Final_Cap.dir/delete_hash.c.s"
	D:\Mingw\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S D:\CLionProjects\Capture\delete_hash.c -o CMakeFiles\Final_Cap.dir\delete_hash.c.s

# Object files for target Final_Cap
Final_Cap_OBJECTS = \
"CMakeFiles/Final_Cap.dir/main.c.obj" \
"CMakeFiles/Final_Cap.dir/Capture.c.obj" \
"CMakeFiles/Final_Cap.dir/Configure.c.obj" \
"CMakeFiles/Final_Cap.dir/hash.c.obj" \
"CMakeFiles/Final_Cap.dir/delete_hash.c.obj"

# External object files for target Final_Cap
Final_Cap_EXTERNAL_OBJECTS =

Final_Cap.exe: CMakeFiles/Final_Cap.dir/main.c.obj
Final_Cap.exe: CMakeFiles/Final_Cap.dir/Capture.c.obj
Final_Cap.exe: CMakeFiles/Final_Cap.dir/Configure.c.obj
Final_Cap.exe: CMakeFiles/Final_Cap.dir/hash.c.obj
Final_Cap.exe: CMakeFiles/Final_Cap.dir/delete_hash.c.obj
Final_Cap.exe: CMakeFiles/Final_Cap.dir/build.make
Final_Cap.exe: CMakeFiles/Final_Cap.dir/linklibs.rsp
Final_Cap.exe: CMakeFiles/Final_Cap.dir/objects1.rsp
Final_Cap.exe: CMakeFiles/Final_Cap.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking C executable Final_Cap.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\Final_Cap.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Final_Cap.dir/build: Final_Cap.exe

.PHONY : CMakeFiles/Final_Cap.dir/build

CMakeFiles/Final_Cap.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\Final_Cap.dir\cmake_clean.cmake
.PHONY : CMakeFiles/Final_Cap.dir/clean

CMakeFiles/Final_Cap.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" D:\CLionProjects\Capture D:\CLionProjects\Capture D:\CLionProjects\Capture\cmake-build-debug D:\CLionProjects\Capture\cmake-build-debug D:\CLionProjects\Capture\cmake-build-debug\CMakeFiles\Final_Cap.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Final_Cap.dir/depend

