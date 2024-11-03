#include <pybind11/pybind11.h>
#include <geek/process/process.h>

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

namespace py = pybind11;

PYBIND11_MODULE(geek, m) {
    m.doc() = R"pbdoc(
    )pbdoc";

    m.def("test", [](int jj) {});

    py::class_<geek::Address>(m, "Address")
        .def(py::init<geek::Process*, uint64_t>(), py::arg("proc"), py::arg("addr"))
        .def("read", static_cast<std::optional<std::vector<uint8_t>>(geek::Address::*)(size_t) const>(&geek::Address::Read), py::arg("size"))
        .def("write", &geek::Address::Write, py::arg("buf"), py::arg("len"), py::arg("force") = false)
        .def("addr", &geek::Address::addr);
    
    py::class_<geek::Process>(m, "Process")
        .def("at", &geek::Process::At);
    
    m.attr("this_proc") = geek::ThisProcess;

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}