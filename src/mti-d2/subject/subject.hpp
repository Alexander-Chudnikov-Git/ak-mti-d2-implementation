#ifndef SUBJECT_HPP
#define SUBJECT_HPP

#include <string>

#include "akrypt-manager.hpp"
#include "mti-d2-common.hpp"

namespace MTI_D2
{
/**
 * @brief      Класс субьекта криптографического протокола MTI-D2
 *
 *             Обеспечивает:
 *              - Управление данными между субьектами (сертификаты, ключи)
 *              - Генерацию параметров протокола
 *              - Выполнение криптографических вычислений
 *              - Взаимную проверку участников
 *
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
    bool extractCASerialNumber();
    bool extractExternCertId();
    bool extractExternPublicKey();
    bool checkExternEPoint();
    bool findExternCert();
    bool verifyCaSerialNumber();
    bool verifyWCType();
    bool verifyExternCa();
    bool verifyXDiff();
    bool verifyPDiff();

public:
    void setE_s_point(const wpoint& E_s_point);
    void setE_e_point(const wpoint& E_e_point);
    void setQ_s_point(const wpoint& Q_s_point);
    void setQ_e_point(const wpoint& Q_e_point);
    void setС_s_point(const wpoint& С_s_point);
    void setС_e_point(const wpoint& С_e_point);
    void setN_ca_num(const ak_uint8* ca_serialnum, ak_uint32 ca_serialnum_len);
    void setN_s_num(const ak_uint8* s_serialnum, ak_uint32 s_serialnum_len);
    void setN_e_num(const ak_uint8* e_serialnum, ak_uint32 e_serialnum_len);
    void setReq_s(bool req);
    void setReq_e(bool req);
    void set_e_s_id(wcurve_id_t s_wc_id);
    void set_e_e_id(wcurve_id_t e_wc_id);

    void setCert_s(UTILS::AkryptCertificate cert_s);
    void setCert_e(UTILS::AkryptCertificate cert_e);

public:
    const ak_uint64* getXi_s_key() const;
    const ak_uint64* getXi_e_key() const;
    const ak_uint64* getXi_se_key() const;
    const ak_uint64* getXi_es_key() const;
    const wpoint getE_s_point() const;
    const wpoint getE_e_point() const;
    const wpoint getQ_s_point() const;
    const wpoint getQ_e_point() const;
    const wpoint getС_s_point() const;
    const wpoint getС_e_point() const;
    const ak_uint8* getN_ca_num() const;
    const ak_uint8* getN_s_num() const;
    const ak_uint8* getN_e_num() const;
    ak_uint32 getN_ca_num_len() const;
    ak_uint32 getN_s_num_len() const;
    ak_uint32 getN_e_num_len() const;
    bool getReq_s() const;
    bool getReq_e() const;
    wcurve_id_t get_e_s_id() const;
    wcurve_id_t get_e_e_id() const;

    UTILS::AkryptCertificate getCert_s();
    UTILS::AkryptCertificate getCert_e();

private:
    std::string m_subject_name;

    bool m_initialized = {false};

    UTILS::AkryptCertificate m_cert_ca = {nullptr};
    UTILS::AkryptCertificate m_cert_s  = {nullptr};
    UTILS::AkryptCertificate m_cert_e  = {nullptr};
    UTILS::AkryptSkey        m_d_s_key = {nullptr};

    const char* m_id_s = {nullptr};
    const char* m_id_e = {nullptr};

    /** s stands for 'self' and e for 'extern', so is subject is A, then 's -> a' 'e -> b' **/
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

