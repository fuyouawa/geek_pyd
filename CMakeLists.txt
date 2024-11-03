cmake_minimum_required(VERSION 3.4...3.18)
set(PROJ_NAME geek)
project(${PROJ_NAME})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(THIRD_PARTY_DIR ${PROJECT_SOURCE_DIR}/third-party)
set(PYBIND11_HEADER_PATH ${THIRD_PARTY_DIR}/pybind11/include)
set(GEEK_HEADER_PATH ${THIRD_PARTY_DIR}/geek-cpp/include)

include_directories(${PYBIND11_HEADER_PATH})
include_directories(${GEEK_HEADER_PATH})

set(GEEK_LIB_ALIAS geek_cpp)
add_subdirectory(${THIRD_PARTY_DIR}/geek-cpp)
add_subdirectory(${THIRD_PARTY_DIR}/pybind11)

pybind11_add_module(${PROJ_NAME} src/main.cpp)

target_link_libraries(${PROJ_NAME} PRIVATE geek_cpp)

# EXAMPLE_VERSION_INFO is defined by setup.py and passed into the C++ code as a
# define (VERSION_INFO) here.
target_compile_definitions(${PROJ_NAME}
                           PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})