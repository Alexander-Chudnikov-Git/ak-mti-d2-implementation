/**
 * @file       <certificate-common.hpp>
 * @brief      Заголовочный файл с общими определениями сертификатов
 *
 *             Константы и перечисления для работы с сертификатами.
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
    DAY   = 24 * 60 * 60,
    MONTH = DAY * 30,
    YEAR  = MONTH * 12
};

}
#endif // CERTIFICATE_COMMON_HPP
