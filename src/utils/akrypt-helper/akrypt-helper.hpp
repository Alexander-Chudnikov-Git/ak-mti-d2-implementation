/**
 * @file       <akrypt-helper.hpp>
 * @brief      Заголовочный файл для класса AkryptHelper
 *
 *             Утилиты для работы с криптографическими операциями.
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

#ifndef AKRYPT_HELPER_HPP
#define AKRYPT_HELPER_HPP

#include <string_view>

#include "akrypt-manager.hpp"
#include "akrypt-certificate.hpp"
#include "akrypt-skey.hpp"

namespace UTILS
{
/**
 * @brief      Класс - помощник для работы с библиотекой libakrypt
 *
 *             Содержит статические методы для:
 *              - Загрузки сертификатов и ключей
 *              - Генерации случайных значений
 *              - Обработки ошибок
 *              - Вспомогательных операций отладки
 *
 */
class AkryptHelper
{
public:
    /**
     * @brief      Загрузка сертификата из файла
     * 
     * @param[in]  certificate_path  Путь к файлу сертификата
     * @param[in]  ca_cert           Сертификат удостоверяющего центра для проверки подписи (по умолчанию nullptr)
     * @return     Объект сертификата или пустой объект при ошибке (вызов AkryptCertificate())
     * 
     */
    static AkryptCertificate loadCertificate(const std::string& certificate_path, AkryptCertificate ca_cert = nullptr);

    /**
     * @brief      Освобождение ресурсов сертификата
     * 
     * @param[in]  cert  Указатель на сертификат
     * 
     */
    static void destroyCertificate(ak_certificate cert);

    /**
     * @brief      Загрузка ключа из файла
     * 
     * @param[in]  skey_path  Путь к файлу ключа
     * @return     Объект ключа или пустой объект при ошибке
     */
    static AkryptSkey loadSkey(const std::string& skey_path);

    /**
     * @brief      Генерация криптографически безопасного случайного числа
     * 
     * @param[out] scalar  Буфер для записи сгенерированных данных
     * @param[in]  length  Размер буфера в байтах
     * @return     true если генерация прошла успешно
     * 
     */
    static bool generateRandomScalar(void* scalar, size_t length);

    /**
     * @brief      Получение текстового описания ошибки libakrypt
     * 
     * @param[in]  error  Код ошибки
     * @return     Строковое описание ошибки
     * 
     */
    static std::string_view getAkErrorDescription(int error);

    /**
     * @brief      Лог структуры точки эллиптической кривой
     * 
     * @param[in]  wpoint  Точка кривой для вывода
     * @param[in]  size    Размер данных для вывода
     * 
     * @note       Дебаг функция
     */
    static void logWPoint(struct wpoint& wpoint, const size_t size = ak_mpzn512_size);

    /**
     * @brief      Функция которая превращает точку в строку
     * 
     * @param[in]  wpoint  Точка кривой
     * @param[in]  size    Размер данных для вывода
     * 
     * @return     Возвращает строку которая получилась
     */
    static std::string makePointsToString(struct wpoint& wpoint, const size_t size);
};
}

#endif // AKRYPT_HELPER_HPP
