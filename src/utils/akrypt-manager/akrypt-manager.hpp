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

private:
    AkryptManager();
    ~AkryptManager();

private:
    mutable std::mutex m_mutex;
    ak_function_log*   m_ak_audit = {nullptr};
    bool               m_ak_initialized;
    std::atomic<int>   m_usage_count;
    AkryptSkey         m_ca_skey;

};
}

#endif // AKRYPT_MANAGER_HPP
