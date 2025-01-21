#ifndef CERTIFICATE_COMMON_HPP
#define CERTIFICATE_COMMON_HPP

#include "akrypt-manager.hpp"
#include "akrypt-helper.hpp"
#include "akrypt-certificate.hpp"
#include "akrypt-skey.hpp"

#define CERT_ID_CN "common-name"

namespace MTI_D2
{
enum CERT_V : ak_uint32
{
    ONE   = 0,
    TWO   = 1,
    THREE = 2
};

enum CERT_T : time_t
{
    DAY   = 24 * 60 * 60,
    MONTH = DAY * 30,
    YEAR  = MONTH * 12
};

}
#endif // CERTIFICATE_COMMON_HPP
