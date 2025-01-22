/**
 * @file       <akrypt-skey.hpp>
 * @brief      Заголовочный файл для класса AkryptSkey
 *
 *             Класс для безопасного управления симметричными ключами.
 *
 * @author     CHOO_IS_FOX (@Alexander-Chudnikov-Git)
 * @date       20.01.2025
 * @version    0.0.1
 *
 * @bug        На данный момент баги отсутствуют.
 *
 * @copyright  А. А. Чудников, Абдуллабеков Т. М, Хохлов E. A. 2025
 *
 * @license    Данный проект находится под публичной лицензией GNUv3.
 *
 */

#ifndef AKRYPT_SKEY_HPP
#define AKRYPT_SKEY_HPP

#include <memory>

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace UTILS
{
/**
 * @brief      Класс для безопасного управления симметричными ключами библиотеки libakrypt
 *
 *             Поддерживает копирование, перемещение и проверку состояния ключа.
 */
class AkryptSkey
{
public:
    /**
     * @brief      Конструктор по умолчанию (создаёт неинициализированный ключ)
     */
    AkryptSkey();

    /**
     * @brief      Конструктор с указателем на ak_skey
     * 
     * @param[in]  skey  Указатель на структуру ключа библиотеки libakrypt
     * 
     * @note       Выполняет копирование переданного ключа
     */
    AkryptSkey(ak_skey skey);

    /**
     * @brief      Копирующий конструктор
     * 
     * @param[in]  other  Объект для копирования
     */
    AkryptSkey(const AkryptSkey& other);


    /**
     * @brief  Оператор копирующего присваивания
     */
    AkryptSkey& operator=(const AkryptSkey& other);

    /**
     * @brief      Перемещающий конструктор
     * 
     * @param[in]  other  Временный объект для перемещения
     */
    AkryptSkey(AkryptSkey&& other) noexcept;

    /**
     * @brief      Оператор перемещающего присваивания
     */
    AkryptSkey& operator=(AkryptSkey&& other) noexcept;

    /**
     * @brief      Деструктор
     */
    ~AkryptSkey();

    /**
     * @brief      Получение указателя на ключ
     * 
     * @return     Указатель на внутреннюю структуру ak_skey
     * 
     */
    ak_skey get();

    /**
     * @brief      Проверка инициализации ключа
     * 
     * @return     Возвращает значение m_initialized
     */
    bool isInitialized() const;

    /**
     * @brief      Получение размера ключа в байтах
     * 
     * @return     Размер ключа или 0 если не инициализирован
     */
    size_t getKeySize() const;

    /**
     * @brief      Получение указателя на данные ключа
     * 
     * @return     Константный указатель на байты ключа или nullptr
     */
    const ak_uint8* getKey() const;

private:
    std::shared_ptr<struct skey> m_skey; ///< Умный (shared) указатель на структуру ключа
    bool m_initialized;  ///< Флаг инициализации объекта
};
}

#endif // AKRYPT_SKEY_HPP
