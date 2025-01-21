#ifndef AKRYPT_CERTIFICATE_HPP
#define AKRYPT_CERTIFICATE_HPP

#include <memory>

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace UTILS
{
class AkryptCertificate
{
public:
    AkryptCertificate();
    AkryptCertificate(ak_certificate cert);

    AkryptCertificate(const AkryptCertificate& other);
    AkryptCertificate& operator=(const AkryptCertificate& other);

    AkryptCertificate(AkryptCertificate&& other) noexcept;
    AkryptCertificate& operator=(AkryptCertificate&& other) noexcept;

    ~AkryptCertificate();

    ak_certificate get();

    bool isInitialized();
    bool isCA();

private:
    std::shared_ptr<struct certificate> m_cert;
    bool m_initialized;
};
}

#endif // AKRYPT_CERTIFICATE_HPP
