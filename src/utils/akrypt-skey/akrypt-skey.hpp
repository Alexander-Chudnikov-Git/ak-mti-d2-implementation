#ifndef AKRYPT_SKEY_HPP
#define AKRYPT_SKEY_HPP

#include <memory>

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace UTILS
{
class AkryptSkey
{
public:
    AkryptSkey();
    AkryptSkey(ak_skey skey);

    AkryptSkey(const AkryptSkey& other);
    AkryptSkey& operator=(const AkryptSkey& other);

    AkryptSkey(AkryptSkey&& other) noexcept;
    AkryptSkey& operator=(AkryptSkey&& other) noexcept;

    ~AkryptSkey();

    ak_skey get();

    bool isInitialized() const;
    size_t getKeySize() const;
    const ak_uint8* getKey() const;

private:
    std::shared_ptr<struct skey> m_skey;
    bool m_initialized;
};
}

#endif // AKRYPT_SKEY_HPP
