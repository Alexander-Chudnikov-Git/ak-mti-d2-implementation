#ifndef SUBJECT_HPP
#define SUBJECT_HPP

#include <string>

#include "akrypt-manager.hpp"
#include "mti-d2-common.hpp"

namespace MTI_D2
{
class Subject
{
public:
    Subject() = default;
    /*Subject(const std::string& subject_name,
            UTILS::AkryptCertificate cert_ca,
            UTILS::AkryptCertificate cert_s,
            UTILS::AkryptSkey d_s_key,
            const char* id_e); ///< Не реализовано на данный момент*/
    Subject(const std::string& subject_name,
            UTILS::AkryptCertificate cert_ca,
            UTILS::AkryptCertificate cert_s,
            UTILS::AkryptSkey d_s_key,
            UTILS::AkryptCertificate cert_e);

    ~Subject();

    void initSubject(UTILS::AkryptCertificate cert_ca,
                     UTILS::AkryptCertificate cert_s,
                     UTILS::AkryptSkey d_s_key,
                     UTILS::AkryptCertificate cert_e = {nullptr}/*,
                     const char* id_e = {}*/);

    void initLibAkrypt();

public:
    bool generateRandomXiScalar();
    bool generateRandomXiSEScalar();
    bool calculateEPoint();
    bool calculateСPoint();
    bool calculateQPoint();
    bool extractSerialNumber();
    bool extractCASerialNumber();
    bool extractExternPublicKey();
    bool checkExternEPoint();
    bool findExternCert();
    bool verifyCaSerialNumber();
    bool verifyWCType();
    bool verifyExternCa();
    bool verifyXDiff();
    bool verifyPDiff();
    bool getIdentifierS();
    bool getIdentifierE();
    bool generateH1ValueS();
    bool generateH1ValueE();
    bool generateH2ValueS();
    bool generateH2ValueE();
    bool generateM1ValueS();
    bool generateM1ValueE();
    bool generateMAC();
    bool validateMAC();
    bool generateHMAC();
    bool generateKkey();
    bool encryptXivalue();
    bool decryptXivalue();

public:
    void setR_s_text(const ak_uint64* r_s_text, ak_uint32 r_s_text_len);
    void setR_e_text(const ak_uint64* r_e_text, ak_uint32 r_e_text_len);
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

    void setTE(const char* t_e);

public:
    const ak_uint64* getXi_s_key() const;
    const ak_uint64* getXi_e_key() const;
    const ak_uint64* getXi_se_key() const;
    const ak_uint64* getXi_es_key() const;
    const ak_uint64* getR_s_text() const;
    const ak_uint64* getR_e_text() const;
    const ak_uint64* getK_s_key() const;
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

    char* getIdS() const;
    char* getIdE() const;
    char* getTS()  const;

    UTILS::AkryptCertificate getCert_s();
    UTILS::AkryptCertificate getCert_e();

private:
    std::string m_subject_name;

    bool m_initialized = {false};

    UTILS::AkryptCertificate m_cert_ca = {nullptr};
    UTILS::AkryptCertificate m_cert_s  = {nullptr};
    UTILS::AkryptCertificate m_cert_e  = {nullptr};
    UTILS::AkryptSkey        m_d_s_key = {nullptr};

    char* m_id_s = {nullptr};
    char* m_id_e = {nullptr};

    char* m_H1_s = {nullptr};
    char* m_H2_s = {nullptr};

    char* m_M1_s = {nullptr};

    char* m_X_s = {nullptr};
    char* m_Y_s = {nullptr};

    char* m_T_s = {nullptr};
    char* m_T_e = {nullptr};

    char* m_v_se = {nullptr};
    char* m_v_es = {nullptr};

    /** s stands for 'self' and e for 'extern', so is subject is A, then 's -> a' 'e -> b' **/
    ak_uint64 m_Xi_s_key[4] = {0}; ///< ξ_a
    ak_uint64 m_Xi_e_key[4] = {0}; ///< ξ_b
    ak_uint64 m_Xi_se_key[4] = {0}; ///< ξ_ab
    ak_uint64 m_Xi_es_key[4] = {0}; ///< ξ_ba

    ak_uint64 m_K_se_key[4] = {0}; ///< K_ab

    ak_uint64* m_R_s_text = {nullptr}; ///< R_a
    ak_uint64* m_R_e_text = {nullptr}; ///< R_b

    ak_uint64* m_P_s_text = {nullptr}; ///< P_a

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

