/**
 * @file       <akrypt-manager.hpp>
 * @brief      Заголовочный файл для класса AkryptManager
 *
 *             Синглтон для управления состоянием криптобиблиотеки.
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

#ifndef AKRYPT_MANAGER_HPP
#define AKRYPT_MANAGER_HPP

#include <mutex>
#include <atomic>

#include "akrypt-skey.hpp"

#include <libakrypt-base.h>
#include <libakrypt.h>

namespace UTILS
{
 /**
 * @brief      Синглтон для управления состоянием библиотеки libakrypt
 *
 *             Позволяет:
 *              - Потокобезопасную инициализацию/деинициализацию библиотеки
 *              - Считает число инициализаций библиотеки
 *              - Хранение общего симметричного ключа
 */
class AkryptManager
{
public:
    /**
     * @brief      Получение уникального экземпляра класса
     * 
     * @return     Ссылка на экземпляр AkryptManager
     */
    static AkryptManager& getInstance();

    AkryptManager(const AkryptManager&)            = delete;
    AkryptManager& operator=(const AkryptManager&) = delete;

    /**
     * @brief      Запуск использования библиотеки
     * 
     * @return     true если инициализация прошла успешно или уже выполнена
     * 
     * @note       Увеличивает счётчик инициализаций библиотеки.
     *             Первый вызов инициализирует библиотеку.
     */
    bool startUsing();

    /**
     * @brief      Прекращение использования библиотеки
     * 
     * @note       Уменьшает внутренний счётчик инициализаций.
     *             Последний вызов деинициализирует (destroy вызов) библиотеку.
     */
    void stopUsing();

    /**
     * @brief      Проверка инициализации библиотеки
     * 
     * @return     true если библиотека успешно инициализирована
     */
    bool isInitialized() const;

    /**
     * @brief      Установка ключа удостоверяющего центра
     * 
     * @param[in]  skey  Сам ключ
     * 
     */
    void setCASkey(AkryptSkey skey);

    /**
     * @brief      Получение ключа удостоверяющего центра
     * 
     * @return     Текущий установленный ключ
     */
    AkryptSkey getCASkey();

    /**
     * @brief      Задание сида для HMAC
     * 
     */
    void setHMACSeed(const std::string& seed);

    /**
     * @brief      Получения сида для HMAC
     * 
     */
    std::string getHMACSeed();

    /**
     * @brief      Установка значений для векторов Vba & Vab
     * 
     */
    void setVBAvalue(std::string& value);
    void setVABvalue(std::string& value);

    /**
     * @brief      Установка значений для векторов Uba & Uab
     * 
     */
    void setUBAvalue(std::string& value);
    void setUABvalue(std::string& value);

    /**
     * @brief      Получение значений векторов Vba, Vab, Uba & Uab
     * 
     */
    std::string getVBAvalue();
    std::string getVABvalue();
    std::string getUBAvalue();
    std::string getUABvalue();
    
    /**
     * @brief      Назначение параметра для Uv
     * 
     */
    void setUVvalue(std::string& value);

private:
    AkryptManager();
    ~AkryptManager();

private:
    mutable std::mutex m_mutex; ///< Мьютекс
    ak_function_log*   m_ak_audit = {nullptr}; ///< Аудит либакрипт
    bool               m_ak_initialized; ///< Проверка инициализации либакрипт
    std::atomic<int>   m_usage_count; ///< Сколько обьектов либакрипта используется
    AkryptSkey         m_ca_skey; ///< Ключ сертификата УЦ
    std::string        m_HMAC_seed; ///< Сид HMAC

    std::string m_vba_value; ///< Вектор Vba
    std::string m_vab_value; ///< Вектор Vab
    std::string m_uba_value; ///< Вектор Uba
    std::string m_uab_value; ///< Вектор Uab
};
}

#endif // AKRYPT_MANAGER_HPP
