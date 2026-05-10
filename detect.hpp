#ifndef FLUKS_DETECT_HPP
#define FLUKS_DETECT_HPP

#include <set>
#include <string>

namespace fluks {

const std::set<std::string> &system_ciphers();
const std::set<std::string> &system_hashes();

}

#endif
