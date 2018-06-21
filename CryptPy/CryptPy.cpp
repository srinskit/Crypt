#include <boost/python.hpp>
#include <Crypt.h>


BOOST_PYTHON_MODULE (CryptPy) {
    using namespace boost::python;
    class_<Crypt>("Crypt")
            .def("initialize", &Crypt::initialize)
            .def("terminate", &Crypt::terminate)
            .def("clear_string", &Crypt::clear_string)
            .def("load_private_key", &Crypt::load_private_key)
            .def("add_cert", &Crypt::add_cert)
            .def("rem_cert", &Crypt::rem_cert)
            .def("encrypt", &Crypt::encrypt)
            .def("decrypt", &Crypt::decrypt)
            .def("sign", &Crypt::sign)
            .def("verify", &Crypt::verify)
            .def < bool(Crypt::*)(const std::string&,const std::string&)>("verify_cert", &Crypt::verify_cert)
                                                                                 .def <
                                                                         bool(Crypt::*)(const std::string&,const std::string&,const std::string&)>
    ("verify_cert", &Crypt::verify_cert)
            .def("load_my_cert", &Crypt::load_my_cert)
            .def("stringify_cert", &Crypt::stringify_cert)
            .def("aes_gen_key", &Crypt::aes_gen_key)
            .def < bool(Crypt::*)(const std::string &)>("aes_save_key", &Crypt::aes_save_key)
                                                               .def <
                                                       bool(Crypt::*)(const std::string &)>("aes_save_key", &Crypt::aes_save_key)
            .def("aes_del_key", &Crypt::aes_del_key)
            .def("aes_encrypt", &Crypt::aes_encrypt)
            .def("aes_decrypt", &Crypt::aes_decrypt)
            .def("aes_exist_key", &Crypt::aes_exist_key)
            .def("aes_get_key", &Crypt::aes_get_key);
}
