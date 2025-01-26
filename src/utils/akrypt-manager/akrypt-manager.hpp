#ifndef AKRYPT_MANAGER_HPP
#define AKRYPT_MANAGER_HPP

#include <mutex>
#include <atomic>

#include "akrypt-skey.hpp"

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace UTILS
{
class AkryptManager
{
public:
    static AkryptManager& getInstance();

    AkryptManager(const AkryptManager&)            = delete;
    AkryptManager& operator=(const AkryptManager&) = delete;

    bool startUsing();
    void stopUsing();

    bool isInitialized() const;

    void setCASkey(AkryptSkey skey);
    AkryptSkey getCASkey();

    void setHMACSeed(const std::string& seed);
    std::string getHMACSeed();

    void setVBAvalue(std::string& value);
    void setVABvalue(std::string& value);
    void setUBAvalue(std::string& value);
    void setUABvalue(std::string& value);

    std::string getVBAvalue();
    std::string getVABvalue();
    std::string getUBAvalue();
    std::string getUABvalue();
    
    void setUVvalue(std::string& value);

private:
    AkryptManager();
    ~AkryptManager();

private:
    mutable std::mutex m_mutex;
    ak_function_log*   m_ak_audit = {nullptr};
    bool               m_ak_initialized;
    std::atomic<int>   m_usage_count;
    AkryptSkey         m_ca_skey;
    std::string        m_HMAC_seed;

    std::string m_vba_value;
    std::string m_vab_value;
    std::string m_uba_value;
    std::string m_uab_value;
};
}

#endif // AKRYPT_MANAGER_HPP
