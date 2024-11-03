#include <pybind11/pybind11.h>
#include <geek/process/process.h>
#include <geek/hook/inline_hook.h>

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

    py::class_<geek::ModuleListNode>(m, "ModuleListNode")
        .def(py::init())
        .def(py::init<geek::ModuleList*, uint64_t>(), py::arg("owner"), py::arg("entry"))
        .def("is_x32", &geek::ModuleListNode::IsX32)
        .def("is_end", &geek::ModuleListNode::IsEnd)
        .def("is_valid", &geek::ModuleListNode::IsValid)
        .def("size_of_image", &geek::ModuleListNode::SizeOfImage)
        .def("dll_base", &geek::ModuleListNode::DllBase)
        .def("full_dll_name", &geek::ModuleListNode::FullDllName)
        .def("base_dll_name", &geek::ModuleListNode::BaseDllName)
        .def("__eq__", &geek::ModuleListNode::operator==)
        .def("__ne__", &geek::ModuleListNode::operator!=)
        .def("__str__", &geek::ModuleListNode::BaseDllName)
        .def("__repr__", &geek::ModuleListNode::DebugName);

    py::class_<geek::ModuleList>(m, "ModuleList")
        .def(py::init<geek::Process*>())
        .def("find_by_module_base", &geek::ModuleList::FindByModuleBase)
        .def("find_by_module_name", &geek::ModuleList::FindByModuleName)
        .def("__iter__", [](const geek::ModuleList& self) {
				return py::make_iterator(self.begin(), self.end());
            }, py::keep_alive<0, 1>());
    
    py::class_<geek::Process>(m, "Process")
        .def("at", &geek::Process::At, py::arg("addr"))
        .def("modules", &geek::Process::Modules)
        .def("proc_name", &geek::Process::BaseName)
		.def("__str__", &geek::Process::BaseName)
        .def("__repr__", &geek::Process::DebugName);

    py::enum_<geek::Architecture>(m, "Architecture")
        .value("CURRENT_RUNNING", geek::Architecture::kCurrentRunning)
		.value("X32", geek::Architecture::kX32)
        .value("AMD64", geek::Architecture::kAmd64);

    py::class_<geek::InlineHook::HookContextX32>(m, "HookContextX32")
        .def_readonly("stack", &geek::InlineHook::HookContextX32::stack)
        .def_readonly("esp", &geek::InlineHook::HookContextX32::esp)
        .def_readonly("jmp_addr", &geek::InlineHook::HookContextX32::jmp_addr)
        .def_readonly("forward_page_base", &geek::InlineHook::HookContextX32::forward_page_base)
        .def_readonly("hook_addr", &geek::InlineHook::HookContextX32::hook_addr)
        .def_readonly("reserve", &geek::InlineHook::HookContextX32::reserve)
        .def_readonly("eax", &geek::InlineHook::HookContextX32::eax)
        .def_readonly("ecx", &geek::InlineHook::HookContextX32::ecx)
        .def_readonly("edx", &geek::InlineHook::HookContextX32::edx)
        .def_readonly("ebx", &geek::InlineHook::HookContextX32::ebx)
        .def_readonly("esp_invalid", &geek::InlineHook::HookContextX32::esp_invalid)
        .def_readonly("ebp", &geek::InlineHook::HookContextX32::ebp)
        .def_readonly("esi", &geek::InlineHook::HookContextX32::esi)
        .def_readonly("edi", &geek::InlineHook::HookContextX32::edi)
        .def_readonly("eflags", &geek::InlineHook::HookContextX32::eflags);

    py::class_<geek::InlineHook::HookContextAmd64>(m, "HookContextAmd64")
        .def_readonly("stack", &geek::InlineHook::HookContextAmd64::stack)
        .def_readonly("rsp", &geek::InlineHook::HookContextAmd64::rsp)
        .def_readonly("jmp_addr", &geek::InlineHook::HookContextAmd64::jmp_addr)
        .def_readonly("forward_page_base", &geek::InlineHook::HookContextAmd64::forward_page_base)
        .def_readonly("hook_addr", &geek::InlineHook::HookContextAmd64::hook_addr)
        .def_readonly("reserve", &geek::InlineHook::HookContextAmd64::reserve)
        .def_readonly("rax", &geek::InlineHook::HookContextAmd64::rax)
        .def_readonly("rcx", &geek::InlineHook::HookContextAmd64::rcx)
        .def_readonly("rdx", &geek::InlineHook::HookContextAmd64::rdx)
        .def_readonly("rbx", &geek::InlineHook::HookContextAmd64::rbx)
        .def_readonly("rbp", &geek::InlineHook::HookContextAmd64::rbp)
        .def_readonly("rsp_invalid", &geek::InlineHook::HookContextAmd64::rsp_invalid)
        .def_readonly("rsi", &geek::InlineHook::HookContextAmd64::rsi)
        .def_readonly("rdi", &geek::InlineHook::HookContextAmd64::rdi)
        .def_readonly("r8", &geek::InlineHook::HookContextAmd64::r8)
        .def_readonly("r9", &geek::InlineHook::HookContextAmd64::r9)
        .def_readonly("r10", &geek::InlineHook::HookContextAmd64::r10)
        .def_readonly("r11", &geek::InlineHook::HookContextAmd64::r11)
        .def_readonly("r12", &geek::InlineHook::HookContextAmd64::r12)
        .def_readonly("r13", &geek::InlineHook::HookContextAmd64::r13)
        .def_readonly("r14", &geek::InlineHook::HookContextAmd64::r14)
        .def_readonly("r15", &geek::InlineHook::HookContextAmd64::r15)
        .def_readonly("rflags", &geek::InlineHook::HookContextAmd64::rflags);

    py::class_<geek::InlineHook>(m, "InlineHook")
        .def(py::init<geek::Process*>())
        .def("Install", &geek::InlineHook::Install,
            py::arg("hook_addr"),
            py::arg("callback"),
            py::arg("instr_size") = 0,
            py::arg("save_volatile_register") = true,
            py::arg("arch") = geek::Architecture::kCurrentRunning,
            py::arg("forward_page_size") = 0x1000)
        .def("InstallX86", &geek::InlineHook::InstallX32,
            py::arg("hook_addr"),
            py::arg("callback"),
            py::arg("instr_size") = 0,
            py::arg("save_volatile_register") = true,
            py::arg("forward_page_size") = 0x1000)
        .def("InstallAmd64", &geek::InlineHook::InstallAmd64,
            py::arg("hook_addr"),
            py::arg("callback"),
            py::arg("instr_size") = 0,
            py::arg("save_volatile_register") = true,
            py::arg("forward_page_size") = 0x1000)
        .def("Uninstall", &geek::InlineHook::Uninstall)
        .def("forward_page", &geek::InlineHook::forward_page);
    
    m.def("this_proc", geek::ThisProc, py::return_value_policy::reference);

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}