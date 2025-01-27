/**
 * @file       <subject.hpp>
 * @brief      Заголовочный файл для класса Subject
 *
 *             Класс конкретного субьекта криптографического протокола MTI-D2.
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
#ifndef SUBJECT_HPP
#define SUBJECT_HPP

#include <string>

#include "akrypt-manager.hpp"
#include "mti-d2-common.hpp"

namespace MTI_D2
{
/**
 * @brief      Класс конкретного субьекта криптографического протокола MTI-D2
 */
class Subject
{
public:
    /**
     * @brief      Конструктор по умолчанию
     */
    Subject() = default;

    /**
     * @brief      Конструктор с частичной инициализацией (устаревший)
     * 
     * @param[in]  subject_name  Идентификатор субъекта
     * @param[in]  cert_ca       Сертификат УЦ
     * @param[in]  cert_s        Собственный сертификат
     * @param[in]  d_s_key       Секретный ключ
     * @param[in]  id_e          Идентификатор внешнего участника (не реализовано)
     * 
     * @deprecated Используйте версию с cert_e вместо id_e
     */
    Subject(const std::string& subject_name,
            UTILS::AkryptCertificate cert_ca,
            UTILS::AkryptCertificate cert_s,
            UTILS::AkryptSkey d_s_key,
            const char* id_e); ///< Не реализовано на данный момент

    /**
     * @brief      Основной конструктор с полной инициализацией
     * 
     * @param[in]  subject_name  Идентификатор субъекта
     * @param[in]  cert_ca       Сертификат УЦ
     * @param[in]  cert_s        Собственный сертификат
     * @param[in]  d_s_key       Секретный ключ
     * @param[in]  cert_e        Сертификат внешнего участника
     */
    Subject(const std::string& subject_name,
            UTILS::AkryptCertificate cert_ca,
            UTILS::AkryptCertificate cert_s,
            UTILS::AkryptSkey d_s_key,
            UTILS::AkryptCertificate cert_e);
    /**
     * @brief      Деструктор
     */
    ~Subject();

    /**
     * @brief      Инициализация субъекта параметрами
     * 
     * @param[in]  cert_ca  Сертификат УЦ
     * @param[in]  cert_s   Собственный сертификат
     * @param[in]  d_s_key  Секретный ключ
     * @param[in]  cert_e   Сертификат внешнего участника (опционально)
     * @param[in]  id_e     Идентификатор внешнего участника (опционально)
     */
    void initSubject(UTILS::AkryptCertificate cert_ca,
                     UTILS::AkryptCertificate cert_s,
                     UTILS::AkryptSkey d_s_key,
                     UTILS::AkryptCertificate cert_e = {nullptr},
                     const char* id_e = {});

    /**
     * @brief      Инициализация криптографической библиотеки
     * 
     */
    void initLibAkrypt();

public:
    /**
     * @brief Генерация случайного скаляра ξ_s
     * @return true если генерация успешна
     */
    bool generateRandomXiScalar();

    /**
     * @brief Генерация случайного скаляра ξ_se
     * @return true если генерация успешна
     */
    bool generateRandomXiSEScalar();

    /**
     * @brief Вычисление точки E
     * @return true если вычисление успешно
     */
    bool calculateEPoint();

    /**
     * @brief Вычисление точки С
     * @return true если вычисление успешно
     */
    bool calculateСPoint();
    /**
     * @brief Вычисление точки Q
     * @return true если вычисление успешно
     */
    bool calculateQPoint();

    /**
     * @brief Извлечение серийного номера
     * @return true если вычисление успешно
     */
    bool extractSerialNumber();

    /**
     * @brief Извлечение серийного номера CA сертификата
     * @return true если вычисление успешно
     */
    bool extractCASerialNumber();

    /**
     * @brief Айди внешнего сертификата
     * @return true если вычисление успешно
     */
    bool extractExternCertId();

    /**
     * @brief Внешний публичный ключ
     * @return true если вычисление успешно
     */
    bool extractExternPublicKey();

    /**
     * @brief Проверка точки на эллептической кривой
     * @return true если вычисление успешно
     */
    bool checkExternEPoint();

    /**
     * @brief Поиск внешнего сертификата
     * @return true если вычисление успешно
     */
    bool findExternCert();

    /**
     * @brief Подтверждение серийного номера CA сертификата
     * @return true если вычисление успешно
     */
    bool verifyCaSerialNumber();

    /**
     * @brief Подтверждение эллептической кривой
     * @return true если вычисление успешно
     */
    bool verifyWCType();

    /**
     * @brief Подтверждение внешнего CA
     * @return true если вычисление успешно
     */
    bool verifyExternCa();

    /**
     * @brief Проверка E_e и Q_e
     * @return true если вычисление успешно
     */
    bool verifyXDiff();

    /**
     * @brief Проверка C_e and P
     * @return true если вычисление успешно
     */
    bool verifyPDiff();

public:
    /**
     * @brief Установка точки E_s
     * @param[in] E_s_point Точка эллиптической кривой
     */
    void setE_s_point(const wpoint& E_s_point);

    /**
     * @brief Установка точки E_e
     * @param[in] E_e_point Точка эллиптической кривой
     */
    void setE_e_point(const wpoint& E_e_point);

    /**
     * @brief Установка точки Q_s
     * @param[in] Q_s_point Точка эллиптической кривой
     */
    void setQ_s_point(const wpoint& Q_s_point);

    /**
     * @brief Установка точки Q_e
     * @param[in] Q_e_point Точка эллиптической кривой
     */
    void setQ_e_point(const wpoint& Q_e_point);

    /**
     * @brief Установка точки С_s
     * @param[in] С_s_point Точка эллиптической кривой
     */
    void setС_s_point(const wpoint& С_s_point);

    /**
     * @brief Установка точки С_e
     * @param[in] С_e_point Точка эллиптической кривой
     */
    void setС_e_point(const wpoint& С_e_point);

    /**
     * @brief      Установка серийного номера УЦ
     * 
     * @param[in]  ca_serialnum      Указатель на буфер с серийным номером
     * @param[in]  ca_serialnum_len  Длина данных в байтах (макс 32)
     * 
     */
    void setN_ca_num(const ak_uint8* ca_serialnum, ak_uint32 ca_serialnum_len);

    /**
     * @brief      Установка собственного серийного номера
     * 
     * @param[in]  s_serialnum      Указатель на буфер с серийным номером
     * @param[in]  s_serialnum_len  Длина данных в байтах (макс 32)
     * 
     */
    void setN_s_num(const ak_uint8* s_serialnum, ak_uint32 s_serialnum_len);

    /**
     * @brief      Установка серийного номера внешнего участника
     * 
     * @param[in]  e_serialnum      Указатель на буфер с серийным номером
     * @param[in]  e_serialnum_len  Длина данных в байтах (макс 32)
     * 
     */
    void setN_e_num(const ak_uint8* e_serialnum, ak_uint32 e_serialnum_len);

    /**
     * @brief      Установка флага запроса для локального участника
     * 
     * @param[in]  req  true - требует выполнения операции, false - отмена
     * 
     * @note       Влияет на логику протокола при взаимной аутентификации
     */
    void setReq_s(bool req);

    /**
     * @brief      Установка флага запроса для внешнего участника
     * 
     * @param[in]  req  true - требует выполнения операции, false - отмена
     * 
     * @see        setReq_s()
     */
    void setReq_e(bool req);

    /**
     * @brief      Установка идентификатора эллиптической кривой для локального участника
     * 
     * @param[in]  s_wc_id  Идентификатор кривой из перечисления wcurve_id_t
     * 
     */
    void set_e_s_id(wcurve_id_t s_wc_id);

    /**
     * @brief      Установка идентификатора эллиптической кривой для внешнего участника
     * 
     * @param[in]  e_wc_id  Идентификатор кривой из перечисления wcurve_id_t
     * 
     */
    void set_e_e_id(wcurve_id_t e_wc_id);

    /**
     * @brief      Установка собственного сертификата
     * 
     * @param[in]  cert_s  Объект сертификата
     * 
     */
    void setCert_s(UTILS::AkryptCertificate cert_s);

    /**
     * @brief      Установка сертификата внешнего участника
     * 
     * @param[in]  cert_e  Объект сертификата
     * 
     */
    void setCert_e(UTILS::AkryptCertificate cert_e);

public:
    /**
     * @brief      Получение скаляра ξ_s (локальный участник)
     * 
     * @return     Указатель на массив из 4 элементов ak_uint64
     */
    const ak_uint64* getXi_s_key() const;

    /**
     * @brief      Получение скаляра ξ_e (внешний участник)
     * 
     * @return     Указатель на массив из 4 элементов ak_uint64
     */
    const ak_uint64* getXi_e_key() const;

    /**
     * @brief      Получение скаляра ξ_se (совместное значение)
     * 
     * @return     Указатель на массив из 4 элементов ak_uint64
     */
    const ak_uint64* getXi_se_key() const;

    /**
     * @brief      Получение скаляра ξ_es 
     * 
     * @return     Указатель на массив из 4 элементов ak_uint64
     * @note       Используется для взаимной аутентификации участников
     */
    const ak_uint64* getXi_es_key() const;

    /**
     * @brief      Получение точки E_s (локальный участник)
     * 
     * @return     Копия структуры точки эллиптической кривой
     */
    const wpoint getE_s_point() const;

    /**
     * @brief      Получение точки E_e (внешний участник)
     * 
     * @return     Копия структуры точки эллиптической кривой
     */
    const wpoint getE_e_point() const;

    /**
     * @brief      Получение точки Q_s (локальный участник)
     * 
     * @return     Копия структуры точки эллиптической кривой
     */
    const wpoint getQ_s_point() const;

    /**
     * @brief      Получение точки Q_e (внешний участник)
     * 
     * @return     Копия структуры точки эллиптической кривой
     */
    const wpoint getQ_e_point() const;

    /**
     * @brief      Получение точки С_s (локальные проверочные данные)
     * 
     * @return     Копия структуры точки эллиптической кривой
     */
    const wpoint getС_s_point() const;

    /**
     * @brief      Получение точки С_e (внешние проверочные данные)
     * 
     * @return     Копия структуры точки эллиптической кривой
     */
    const wpoint getС_e_point() const;

    /**
     * @brief      Получение серийного номера УЦ
     * 
     * @return     Указатель на буфер размером до 32 байт
     */
    const ak_uint8* getN_ca_num() const;

    /**
     * @brief      Получение собственного серийного номера
     * 
     * @return     Указатель на буфер размером до 32 байт
     */
    const ak_uint8* getN_s_num() const;

    /**
     * @brief      Получение серийного номера внешнего участника
     * 
     * @return     Указатель на буфер размером до 32 байт
     */
    const ak_uint8* getN_e_num() const;

    /**
     * @brief      Получение длины серийного номера УЦ
     * 
     * @return     Фактическое количество значимых байт в буфере N_ca_num
     */
    ak_uint32 getN_ca_num_len() const;

    /**
     * @brief      Получение длины собственного серийного номера
     * 
     * @return     Фактическое количество байт в буфере N_s_num
     */
    ak_uint32 getN_s_num_len() const;

    /**
     * @brief      Получение длины серийного номера внешнего участника
     * 
     * @return     Фактическое количество байт в буфере N_e_num
     */
    ak_uint32 getN_e_num_len() const;

    /**
     * @brief      Получение состояния флага запроса для локального участника
     * 
     * @return     true - требуется выполнение операции
     * 
     */
    bool getReq_s() const;

    /**
     * @brief      Получение состояния флага запроса для внешнего участника
     * 
     * @return     true - требуется ответная операция
     * 
     */
    bool getReq_e() const;

    /**
     * @brief      Получение идентификатора кривой локального участника
     * 
     * @return     Элемент перечисления wcurve_id_t
     * 
     */
    wcurve_id_t get_e_s_id() const;

    /**
     * @brief      Получение идентификатора кривой внешнего участника
     * 
     * @return     Элемент перечисления wcurve_id_t
     * 
     */
    wcurve_id_t get_e_e_id() const;

    /**
     * @brief      Получение копии собственного сертификата
     * 
     * @return     Объект AkryptCertificate
     * 
     */
    UTILS::AkryptCertificate getCert_s();

    /**
     * @brief      Получение копии сертификата внешнего участника
     * 
     * @return     Объект AkryptCertificate
     * 
     */
    UTILS::AkryptCertificate getCert_e();

private:
    std::string m_subject_name; ///< Уникальный идентификатор участника протокола

    bool m_initialized = {false}; ///< Флаг завершённости инициализации

    UTILS::AkryptCertificate m_cert_ca = {nullptr};///< Сертификат корневого УЦ для проверки цепочки доверия
    UTILS::AkryptCertificate m_cert_s  = {nullptr};///< Собственный сертификат участника 
    UTILS::AkryptCertificate m_cert_e  = {nullptr};///< Сертификат внешнего участника 
    UTILS::AkryptSkey        m_d_s_key = {nullptr};///< Секретный ключ для вычислений 

    const char* m_id_s = {nullptr};///< Идентификатор локального субъекта
    const char* m_id_e = {nullptr};///< Идентификатор внешнего субъекта

    /**
    s обозначает "сам" (self), и e — "внешний" (extern).
    Таким образом, если субъект — это A, то:
    's -> a' (self ссылается на a),
    'e -> b' (extern ссылается на b).
    **/
    ak_uint64 m_Xi_s_key[4] = {0}; ///< ξ_a
    ak_uint64 m_Xi_e_key[4] = {0}; ///< ξ_b
    ak_uint64 m_Xi_se_key[4] = {0}; ///< ξ_ab
    ak_uint64 m_Xi_es_key[4] = {0}; ///< ξ_ba

    wpoint m_E_s_point = {}; ///< E_a
    wpoint m_E_e_point = {}; ///< E_b

    wpoint m_Q_s_point = {}; ///< Q_a
    wpoint m_Q_e_point = {}; ///< Q_b
    wpoint m_Q_se_point = {}; ///< Q_ba
    wpoint m_Q_es_point = {}; ///< Q_ab

    wpoint m_С_s_point = {}; ///< С_a
    wpoint m_С_e_point = {}; ///< С_b

    ak_uint8 m_ca_serialnum[32] = {0}; ///< N_ca
    ak_uint8 m_s_serialnum[32] = {0}; ///< N_a
    ak_uint8 m_e_serialnum[32] = {0}; ///< N_b

    ak_uint32 m_ca_serialnum_length = {0};
    ak_uint32 m_s_serialnum_length = {0};
    ak_uint32 m_e_serialnum_length = {0};

    bool m_req_s = {false}; ///< req_a
    bool m_req_e = {false}; ///< req_b

    wcurve_id_t m_s_wc_id; ///< e_a
    wcurve_id_t m_e_wc_id; ///< e_b
};
}

#endif // SUBJECT_HPP

