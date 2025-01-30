#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "akrypt-manager.hpp"

namespace UTILS
{
AkryptManager& AkryptManager::getInstance()
{
    static AkryptManager instance;
    return instance;
}

bool AkryptManager::startUsing()
{
    std::lock_guard<std::mutex> lock(this->m_mutex);
    if (this->m_usage_count++ == 0)
    {
        spdlog::info(" Creating new instance of akrypt.");
        this->m_ak_audit = ak_function_log_syslog;
        if (ak_libakrypt_create(this->m_ak_audit) != ak_true)
        {
            spdlog::error("Unable to initialize akrypt.");

            this->m_ak_initialized = false;
            ak_libakrypt_destroy();
            this->m_ak_audit = nullptr;
            this->m_usage_count = 0;

            return false;
        }
        this->m_ak_initialized = true;
    }
    return true;
}

void AkryptManager::stopUsing()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (--this->m_usage_count == 0 && this->isInitialized())
    {
        spdlog::info(" All users of libakrypt were stopped. Destroying akrypt instance.");
        ak_libakrypt_destroy();
        this->m_ak_audit = nullptr;
        this->m_ak_initialized = false;
    }

    if (this->m_usage_count < 0)
    {
        this->m_usage_count = 0;
    }
}

bool AkryptManager::isInitialized() const
{
    return this->m_ak_initialized;
}

void AkryptManager::setHMACSeed(const std::string& seed)
{
    this->m_HMAC_seed = seed;
}

std::string AkryptManager::getHMACSeed()
{
    return this->m_HMAC_seed;
}


std::string AkryptManager::getVBAvalue()
{
    return this->m_vba_value;
}

std::string AkryptManager::getVABvalue()
{
    return this->m_vab_value;
}

std::string AkryptManager::getUBAvalue()
{
    return this->m_uba_value;
}

std::string AkryptManager::getUABvalue()
{
    return this->m_uab_value;
}

void AkryptManager::setVBAvalue(std::string& value)
{
    if (value.size() != 16)
    {
        spdlog::error("Invalid uv parameter size provided.");
        return;
    }

    this->m_vba_value = value;
}

void AkryptManager::setVABvalue(std::string& value)
{
    if (value.size() != 16)
    {
        spdlog::error("Invalid uv parameter size provided.");
        return;
    }

    this->m_vab_value = value;
}

void AkryptManager::setUBAvalue(std::string& value)
{
    if (value.size() != 16)
    {
        spdlog::error("Invalid uv parameter size provided.");
        return;
    }

    this->m_uba_value = value;
}

void AkryptManager::setUABvalue(std::string& value)
{
    if (value.size() != 16)
    {
        spdlog::error("Invalid uv parameter size provided.");
        return;
    }

    this->m_uab_value = value;
}

void AkryptManager::setUVvalue(std::string& value)
{
    this->setVBAvalue(value);
    this->setVABvalue(value);
    this->setUBAvalue(value);
    this->setUABvalue(value);
}

AkryptManager::AkryptManager() :
    m_ak_audit(nullptr), m_ak_initialized(false), m_usage_count(0)
{
}

AkryptManager::~AkryptManager()
{
    if (this->isInitialized())
    {
        ak_libakrypt_destroy();
        this->m_ak_audit = nullptr;
        this->m_ak_initialized = false;
    }
}

void AkryptManager::setCASkey(AkryptSkey skey)
{
    this->m_ca_skey = skey;
}

AkryptSkey AkryptManager::getCASkey()
{
    return this->m_ca_skey;
}

}

