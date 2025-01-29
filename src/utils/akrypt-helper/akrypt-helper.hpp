#ifndef AKRYPT_HELPER_HPP
#define AKRYPT_HELPER_HPP

#include <string_view>

#include "akrypt-manager.hpp"
#include "akrypt-certificate.hpp"
#include "akrypt-skey.hpp"

namespace UTILS
{
class AkryptHelper
{
public:
    static AkryptCertificate loadCertificate(const std::string& certificate_path, AkryptCertificate ca_cert = nullptr);
    static void destroyCertificate(ak_certificate cert);

    static AkryptSkey loadSkey(const std::string& skey_path);

    static bool generateRandomScalar(void* scalar, size_t length);

    static std::string_view getAkErrorDescription(int error);

    static void logWPoint(struct wpoint& wpoint, const size_t size = ak_mpzn512_size);

    static std::string makePointsToString(struct wpoint& wpoint, const size_t size);
};
}

#endif // AKRYPT_HELPER_HPP
