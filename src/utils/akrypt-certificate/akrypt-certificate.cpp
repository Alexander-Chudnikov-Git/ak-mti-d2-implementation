#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <cstring>

#include "akrypt-certificate.hpp"
#include "akrypt-manager.hpp"

namespace UTILS
{

AkryptCertificate::AkryptCertificate() :
    m_cert(std::make_shared<struct certificate>()),
    m_initialized(false)
{
    UTILS::AkryptManager::getInstance().startUsing();

    this->m_cert->vkey = {};
    this->m_cert->opts = {};
}

AkryptCertificate::AkryptCertificate(ak_certificate cert) :
    m_cert(std::make_shared<struct certificate>()),
    m_initialized(false)
{
    UTILS::AkryptManager::getInstance().startUsing();

    if (cert != nullptr)
    {
        this->m_cert = std::shared_ptr<struct certificate>(cert, ak_certificate_destroy);
        this->m_initialized = true;
    }
    else
    {
        this->m_cert->vkey = {};
        this->m_cert->opts = {};
    }
}

AkryptCertificate::AkryptCertificate(const AkryptCertificate& other) :
    m_cert(std::make_shared<struct certificate>()),
    m_initialized(false)
{
    UTILS::AkryptManager::getInstance().startUsing();

    if (other.m_cert)
    {
        *this->m_cert = *other.m_cert;

        this->m_initialized = true;
    }
}

AkryptCertificate& AkryptCertificate::operator=(const AkryptCertificate& other)
{
    UTILS::AkryptManager::getInstance().startUsing();

    this->m_initialized = false;

    if (this != &other)
    {
        if (other.m_cert)
        {
            if (!this->m_cert)
            {
                this->m_cert = std::make_shared<struct certificate>();
            }

            *this->m_cert = *other.m_cert;

            this->m_initialized = true;
        }
        else
        {
            this->m_cert.reset();
        }
    }
    return *this;
}

AkryptCertificate::AkryptCertificate(AkryptCertificate&& other) noexcept :
    m_cert(std::move(other.m_cert)),
    m_initialized(true)
{
    UTILS::AkryptManager::getInstance().startUsing();
}

AkryptCertificate& AkryptCertificate::operator=(AkryptCertificate&& other) noexcept
{
    UTILS::AkryptManager::getInstance().startUsing();

    if (this != &other)
    {
        m_cert = std::move(other.m_cert);
    }
    return *this;
}

AkryptCertificate::~AkryptCertificate()
{
    UTILS::AkryptManager::getInstance().stopUsing();
}

ak_certificate AkryptCertificate::get()
{
    if (this->m_initialized)
    {
        return this->m_cert.get();
    }

    return nullptr;
}

bool AkryptCertificate::isInitialized()
{
    return this->m_initialized;
}

bool AkryptCertificate::isCA()
{
    if (this->m_cert->opts.ext_ca.is_present != ak_true)
    {
        return false;
    }

    if (this->m_cert->opts.ext_ca.value == ak_true)
    {
        return true;
    }

    return false;
}

}
