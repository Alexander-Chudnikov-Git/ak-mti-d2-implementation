#ifndef CERTIFICATE_COMMON_HPP
#define CERTIFICATE_COMMON_HPP

#include "akrypt-manager.hpp"
#include "akrypt-helper.hpp"
#include "akrypt-certificate.hpp"
#include "akrypt-skey.hpp"

/**
 * @def CERT_ID_CN
 * @brief Стандартный идентификатор поля "Common Name" в сертификатах
 * 
 * Используется для задания общего имени субъекта в соответствии 
 * со стандартом X.509 для цифровых сертификатов.
 */
#define CERT_ID_CN "common-name"


namespace MTI_D2
{
/**
 * @enum CERT_V
 * @brief Перечисление версий сертификатов
 * 
 * Соответствует версиям стандарта X.509:
 * - ONE: Версия 1 (базовая)
 * - TWO: Версия 2 (с расширениями)
 * - THREE: Версия 3 (поддержка современных расширений)
 */
enum CERT_V : ak_uint32
{
    ONE   = 0, ///< X.509v1 (RFC 1422)
    TWO   = 1, ///< X.509v2 (устаревшая)
    THREE = 2 ///< X.509v3 (RFC 5280)
};

/**
 * @enum CERT_T
 * @brief Временные константы для срока действия сертификатов
 * 
 * Значения представлены в секундах:
 * - DAY: 24 часа
 * - MONTH: 30 дней
 * - YEAR: 365 дней
 * 
 * @note Для упрощения расчетов месяц считается как 30 дней, 
 *       год как 365 дней без учета високосных лет
 */
enum CERT_T : time_t
{
    DAY   = 24 * 60 * 60, ///< 86400 секунд
    MONTH = DAY * 30, ///< 2592000 секунд
    YEAR  = MONTH * 12 ///< 31536000 секунд
};

}
#endif // CERTIFICATE_COMMON_HPP
