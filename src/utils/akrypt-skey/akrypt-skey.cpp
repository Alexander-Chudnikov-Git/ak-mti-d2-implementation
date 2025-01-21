#include "akrypt-skey.hpp"

#include <libakrypt.h>

namespace UTILS
{
AkryptSkey::AkryptSkey() :
    m_skey(std::make_shared<struct skey>()),
    m_initialized(false)
{
}

AkryptSkey::AkryptSkey(ak_skey skey) :
    m_skey(nullptr),
    m_initialized(false)
{
    if (skey != nullptr)
    {
        this->m_skey = std::shared_ptr<struct skey>(skey, ak_skey_delete);
        this->m_initialized = true;
    }
}

AkryptSkey::AkryptSkey(const AkryptSkey& other) :
    m_skey(other.m_skey),
    m_initialized(other.m_initialized)
{
}

AkryptSkey& AkryptSkey::operator=(const AkryptSkey& other)
{
    if (this != &other)
    {
        this->m_skey = other.m_skey;
        this->m_initialized = other.m_initialized;
    }
    return *this;
}

AkryptSkey::AkryptSkey(AkryptSkey&& other) noexcept :
    m_skey(std::move(other.m_skey)),
    m_initialized(other.m_initialized)
{
    other.m_initialized = false;
}

AkryptSkey& AkryptSkey::operator=(AkryptSkey&& other) noexcept
{
    if (this != &other)
    {
        this->m_skey = std::move(other.m_skey);
        this->m_initialized = other.m_initialized;
        other.m_initialized = false;
    }
    return *this;
}

AkryptSkey::~AkryptSkey() = default;

ak_skey AkryptSkey::get()
{
    return m_skey.get();
}

bool AkryptSkey::isInitialized() const
{
    return m_initialized;
}

size_t AkryptSkey::getKeySize() const
{
    if (!this->m_initialized)
    {
        return 0;
    }

    return this->m_skey->key_size;
}

const ak_uint8* AkryptSkey::getKey() const
{
    if (!this->m_initialized)
    {
        return nullptr;
    }

    return this->m_skey->key;
}
} // namespace UTILS
