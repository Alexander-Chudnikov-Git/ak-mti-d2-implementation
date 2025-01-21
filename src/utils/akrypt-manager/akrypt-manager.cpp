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
            spdlog::error(" Unable to initialize akrypt.");

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

