#ifndef DETECT_HPP
#define DETECT_HPP

#include <set>
#include <string>

#include "errors.hpp"

namespace luks {

const std::set<std::string> &system_ciphers();
const std::set<std::string> &system_hashes();

}

#endif
