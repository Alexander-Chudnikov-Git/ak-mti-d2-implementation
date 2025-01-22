#ifndef AKRYPT_CERTIFICATE_HPP
#define AKRYPT_CERTIFICATE_HPP

#include <memory>

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace UTILS
{
/**
 * @brief      Класс для работы с сертификатами libakrypt
 *
 *             Обеспечивает безопасное управление памятью и проверку 
 *             основных свойств сертификатов. Поддерживает копирование, 
 *             перемещение и проверку статуса CA.
 */
class AkryptCertificate
{
public:
     /**
     * @brief      Конструктор по умолчанию
     */
    AkryptCertificate();

    /**
     * @brief      Конструктор из указателя на сертификат
     * 
     * @param[in]  cert  Указатель на структуру сертификата libakrypt
     * 
     * @note       Выполняет копирование переданного сертификата
     */
    AkryptCertificate(ak_certificate cert);

    /**
     * @brief      Копирующий конструктор
     * 
     * @param[in]  other  Объект для копирования
     */
    AkryptCertificate(const AkryptCertificate& other);

    /**
     * @brief      Оператор копирующего присваивания
     */
    AkryptCertificate& operator=(const AkryptCertificate& other);

    /**
     * @brief      Перемещающий конструктор
     * 
     * @param[in]  other  Временный объект для перемещения
     */
    AkryptCertificate(AkryptCertificate&& other) noexcept;

    /**
     * @brief      Оператор перемещающего присваивания
     */
    AkryptCertificate& operator=(AkryptCertificate&& other) noexcept;

    /**
     * @brief      Деструктор
     */
    ~AkryptCertificate();

    /**
     * @brief      Получение указателя на сертификат
     * 
     * @return     Указатель на внутреннюю структуру ak_certificate
     * 
     */
    ak_certificate get();

    /**
     * @brief      Проверка инициализации сертификата
     * 
     * @return     true если сертификат успешно загружен
     */
    bool isInitialized();

    /**
     * @brief      Проверка, является ли сертификат центра сертификации (CA)
     * 
     * @return     true если сертификат CA
     *      */
    bool isCA();

private:
    std::shared_ptr<struct certificate> m_cert; ///< Умный указатель на структуру сертификата
    bool m_initialized; ///< Флаг инициализации объекта
};
}

#endif // AKRYPT_CERTIFICATE_HPP
