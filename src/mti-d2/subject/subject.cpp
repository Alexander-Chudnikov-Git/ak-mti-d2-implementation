#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "subject.hpp"

namespace MTI_D2
{
/*Subject::Subject(const std::string& subject_name,
                 UTILS::AkryptCertificate cert_ca,
                 UTILS::AkryptCertificate cert_s,
                 UTILS::AkryptSkey d_s_key,
                 const char* id_e):
    m_subject_name(subject_name),
    m_initialized(false)
{
      this->initSubject(cert_ca, cert_s, d_s_key, {nullptr}, id_e);
}*/

Subject::Subject(const std::string& subject_name,
                 UTILS::AkryptCertificate cert_ca,
                 UTILS::AkryptCertificate cert_s,
                 UTILS::AkryptSkey d_s_key,
                 UTILS::AkryptCertificate cert_e):
    m_subject_name(subject_name),
    m_initialized(false)
{
      this->initSubject(cert_ca, cert_s, d_s_key, cert_e/*, {}*/);
}

Subject::~Subject()
{
    if (this->m_id_e != nullptr)
    {
        delete[] this->m_id_e;
        this->m_id_e = nullptr;
    }

    UTILS::AkryptManager::getInstance().stopUsing();
}

void Subject::initSubject(UTILS::AkryptCertificate cert_ca,
                          UTILS::AkryptCertificate cert_s,
                          UTILS::AkryptSkey d_s_key,
                          UTILS::AkryptCertificate cert_e/*,
                          const char* id_e*/)
{
    if (cert_ca.isInitialized())
    {
        this->m_cert_ca = cert_ca;
    }

    if (cert_s.isInitialized())
    {
        this->m_cert_s = cert_s;
    }

    if (d_s_key.isInitialized())
    {
        this->m_d_s_key = d_s_key;
    }

    if (cert_e.isInitialized())
    {
        this->m_cert_e = cert_e;
        this->m_req_s = false;
    }
    else
    {
        this->m_req_s = true;
    }

    /*this->m_id_e = id_e;*/

    spdlog::info(" Subject '{}' initialized.", this->m_subject_name);

    this->initLibAkrypt();

    this->m_initialized = true;

    // DEBUG
    /*
    auto pubkey_wcurve = this->m_cert_s.get()->vkey.wc;

    size_t ts = ak_hash_get_tag_size(&this->m_cert_s.get()->vkey.ctx);

    spdlog::info("mwp_nq_str: {}", pubkey_wcurve->nq);
    spdlog::info("mwp_n_str: {}", pubkey_wcurve->n);

    std::string mwp_px_str = ak_mpzn_to_hexstr(pubkey_wcurve->point.x, ( ts>>3 ));
    std::string mwp_py_str = ak_mpzn_to_hexstr(pubkey_wcurve->point.y, ( ts>>3 ));
    std::string mwp_pz_str = ak_mpzn_to_hexstr(pubkey_wcurve->point.z, ( ts>>3 ));

    spdlog::info("mwp_px_str: {}", mwp_px_str);
    spdlog::info("mwp_py_str: {}", mwp_py_str);
    spdlog::info("mwp_pz_str: {}", mwp_pz_str);

    for (int i = 1; i <= 10000; ++i)
    {
        ak_uint64 k[4] = { static_cast<ak_uint64>(i), 0x0000000000000000LL, 0x0000000000000000LL, 0x0000000000000000LL };

        struct wpoint multiple_wpoint;

        ak_wpoint_pow(&multiple_wpoint, &pubkey_wcurve->point, k, sizeof(k), pubkey_wcurve); // Возводим точку в кратную степень

        std::string mwp_wk_str = ak_mpzn_to_hexstr(k, (ts >> 3));

        size_t non_zero_pos = mwp_wk_str.find_first_not_of('0');
        if (non_zero_pos != std::string::npos)
        {
            mwp_wk_str = mwp_wk_str.substr(non_zero_pos);
        }


        std::string mwp_wpx_str = ak_mpzn_to_hexstr(multiple_wpoint.x, (ts >> 3));
        std::string mwp_wpy_str = ak_mpzn_to_hexstr(multiple_wpoint.y, (ts >> 3));
        std::string mwp_wpz_str = ak_mpzn_to_hexstr(multiple_wpoint.z, (ts >> 3));

        spdlog::info("{}Px: {}", mwp_wk_str, mwp_wpx_str);
        spdlog::info("{}Py: {}", mwp_wk_str, mwp_wpy_str);
        spdlog::info("{}Pz: {}", mwp_wk_str, mwp_wpz_str);
    }*/
}

void Subject::initLibAkrypt()
{
    UTILS::AkryptManager::getInstance().startUsing();
}

// ======================== Executor step helpers ========================

bool Subject::generateRandomXiScalar()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate random Xi point. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    struct random generator;

    if (ak_random_create_lcg(&generator) != ak_error_ok)
    {
        spdlog::error(" Unable to initialize LCG random number generator.");
        return false;
    }

    // Add check for for Fq
    if (ak_random_ptr(&generator, this->m_Xi_s_key, sizeof(this->m_Xi_s_key)) != ak_error_ok)
    {
        spdlog::error(" Failed to generate random values.");
        ak_random_destroy(&generator);
        return false;
    }

    ak_random_destroy(&generator);

    spdlog::info(" {} Xi_s scalar:", this->m_subject_name);
    spdlog::info("     {}", ak_mpzn_to_hexstr(this->m_Xi_s_key, ak_mpzn256_size));

    return true;
}

bool Subject::generateRandomXiSEScalar()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate random Xi point. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    struct random generator;

    if (ak_random_create_lcg(&generator) != ak_error_ok)
    {
        spdlog::error(" Unable to initialize LCG random number generator.");
        return false;
    }

    // Add check for for Fq
    if (ak_random_ptr(&generator, this->m_Xi_se_key, sizeof(this->m_Xi_se_key)) != ak_error_ok)
    {
        spdlog::error(" Failed to generate random values.");
        ak_random_destroy(&generator);
        return false;
    }

    ak_random_destroy(&generator);

    spdlog::info(" {} Xi_se scalar:", this->m_subject_name);
    spdlog::info("     {}", ak_mpzn_to_hexstr(this->m_Xi_se_key, ak_mpzn256_size));

    return true;
}

bool Subject::calculateEPoint()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to calculate E point. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    auto pubkey_wcurve = this->m_cert_s.get()->vkey.wc;

    ak_wpoint_pow(&this->m_E_s_point, &pubkey_wcurve->point, this->m_Xi_s_key, sizeof(this->m_Xi_s_key), pubkey_wcurve);

    ak_wpoint_reduce(&this->m_E_s_point, pubkey_wcurve);

    spdlog::info(" {} E_s point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_E_s_point, ak_mpzn256_size);

    return true;
}

bool Subject::calculateСPoint()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to calculate C point. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    this->m_С_s_point = this->m_Q_e_point;

    ak_wpoint_add(&this->m_С_s_point, &this->m_E_e_point, this->m_cert_e.get()->vkey.wc);

    ak_wpoint_reduce(&this->m_С_s_point, this->m_cert_e.get()->vkey.wc);

    spdlog::info(" {} C_e point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_С_s_point, ak_mpzn256_size);

    return true;
}


bool Subject::calculateQPoint()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to calculate Q point. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    wpoint temp_point_1 = {};
    wpoint temp_point_2 = {};

    ak_wpoint_pow(&temp_point_1, &this->m_С_s_point, this->m_Xi_e_key, sizeof(this->m_Xi_e_key), this->m_cert_s.get()->vkey.wc);
    ak_wpoint_pow(&temp_point_2, &this->m_С_s_point, reinterpret_cast<ak_uint64 *>(this->m_d_s_key.get()->key), (this->m_d_s_key.get()->key_size / 4), this->m_cert_s.get()->vkey.wc); ///< Yeah, looks painfull
    ak_wpoint_set_wpoint(&this->m_Q_se_point, &temp_point_1, this->m_cert_s.get()->vkey.wc);
    ak_wpoint_add(&this->m_Q_se_point, &temp_point_2, this->m_cert_s.get()->vkey.wc);

    ak_wpoint_reduce(&this->m_Q_se_point, this->m_cert_s.get()->vkey.wc);

    spdlog::info("{} Q_se point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_Q_se_point, ak_mpzn256_size);

    return true;
}

bool Subject::extractSerialNumber()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract serial number. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    std::memcpy(this->m_s_serialnum, this->m_cert_s.get()->opts.serialnum, this->m_cert_s.get()->opts.serialnum_length);
    this->m_s_serialnum_length = this->m_cert_s.get()->opts.serialnum_length;

    spdlog::info(" {} serial number:", this->m_subject_name);
    spdlog::info("     {}", ak_ptr_to_hexstr(this->m_s_serialnum, this->m_s_serialnum_length, ak_false));

    return true;
}

bool Subject::extractCASerialNumber()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract CA serial number. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    std::memcpy(this->m_ca_serialnum, this->m_cert_ca.get()->opts.serialnum, this->m_cert_ca.get()->opts.serialnum_length);
    this->m_ca_serialnum_length = this->m_cert_ca.get()->opts.serialnum_length;

    spdlog::info(" {} CA serial number:", this->m_subject_name);
    spdlog::info("     {}", ak_ptr_to_hexstr(this->m_ca_serialnum, this->m_ca_serialnum_length, ak_false));

    return true;
}

bool Subject::extractExternCertId()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract subject ID. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    // I have no idea what's subject id

    return true;
}

bool Subject::extractExternPublicKey()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract subject ID. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    this->m_Q_e_point = this->m_cert_e.get()->vkey.qpoint;
    spdlog::info(" {} Extern Q point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_Q_e_point, ak_mpzn256_size);

    return true;
}

bool Subject::checkExternEPoint()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable verify extern E point. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    this->m_s_wc_id = this->m_cert_s.get()->vkey.wc->id;

    if (!ak_wpoint_is_ok(&this->m_E_e_point, this->m_cert_s.get()->vkey.wc))
    {
        spdlog::error(" Extern E point is not on the curve. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" Extern E point is on the curve. Subject {}.", this->m_subject_name);

    return true;
}

bool Subject::findExternCert()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to find extern certificate. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    // Add search by serial number
    // we should search for m_cert_e using m_e_serialnum

    if (this->m_req_s) ///< Do we have extern cert request/
    {
        spdlog::info(" Extern certificate not found. Subject {}.", this->m_subject_name);
        return true;
    }

    if (!this->m_cert_e.isInitialized()) ///< Do we have valid extern cert ?
    {
        spdlog::info(" Extern certificate not found. Subject {}.", this->m_subject_name);
        this->m_req_s = true;
        return true;
    }

    if (std::memcmp(this->m_cert_e.get()->opts.serialnum, this->m_e_serialnum, this->m_e_serialnum_length) != 0)
    {
        spdlog::error(" Extern certificate has wrong serial number. Subject {}.", this->m_subject_name);
        spdlog::error(" Expected serial number:");
        spdlog::error("     {}", ak_ptr_to_hexstr(this->m_e_serialnum, this->m_e_serialnum_length, ak_false));
        spdlog::error(" Real serial number:");
        spdlog::error("     {}", ak_ptr_to_hexstr(this->m_cert_e.get()->opts.serialnum, this->m_cert_e.get()->opts.serialnum_length, ak_false));
        return false;
    }

    spdlog::info(" Extern certificate validated. Subject {}.", this->m_subject_name);

    return true;
}

bool Subject::verifyCaSerialNumber()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to verify CA certficate. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    if (std::memcmp(this->m_cert_ca.get()->opts.serialnum, this->m_ca_serialnum, this->m_ca_serialnum_length) != 0)
    {
        spdlog::error(" CA certificate has wrong serial number. Subject {}.", this->m_subject_name);
        spdlog::error(" Expected serial number:");
        spdlog::error("     {}", ak_ptr_to_hexstr(this->m_ca_serialnum, this->m_ca_serialnum_length, ak_false));
        spdlog::error(" Real serial number:");
        spdlog::error("     {}", ak_ptr_to_hexstr(this->m_cert_ca.get()->opts.serialnum, this->m_cert_ca.get()->opts.serialnum_length, ak_false));
        return false;
    }

    spdlog::info(" CA certificate validated. Subject {}.", this->m_subject_name);

    return true;
}

bool Subject::verifyWCType()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to verify elliptic curve id. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    if (this->m_e_wc_id != this->m_cert_s.get()->vkey.wc->id)
    {
        spdlog::error(" Elliptic curves differ from each other. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" Elliptic curve validated. Subject {}.", this->m_subject_name);

    return true;
}

bool Subject::verifyExternCa()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to verify extern certificate using CA. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    if (std::memcmp(this->m_cert_ca.get()->opts.serialnum, this->m_cert_e.get()->opts.issuer_serialnum, this->m_cert_ca.get()->opts.serialnum_length) != 0)
    {
        spdlog::error(" Extern certificate is generated by other CA. Subject {}.", this->m_subject_name);
        spdlog::error(" Expected serial number:");
        spdlog::error("     {}", ak_ptr_to_hexstr(this->m_cert_ca.get()->opts.serialnum, this->m_cert_ca.get()->opts.serialnum_length, ak_false));
        spdlog::error(" Real serial number:");
        spdlog::error("     {}", ak_ptr_to_hexstr(this->m_cert_e.get()->opts.issuer_serialnum, this->m_cert_e.get()->opts.issuer_serialnum_length, ak_false));
        return false;
    }

    time_t now = time( NULL );

    if((this->m_cert_ca.get()->opts.time.not_before > now) || (this->m_cert_ca.get()->opts.time.not_after < now))
    {
        spdlog::error(" CA certificate has expired. {}.", this->m_subject_name);
        return false;
    }

        if((this->m_cert_e.get()->opts.time.not_before > now) || (this->m_cert_e.get()->opts.time.not_after < now))
    {
        spdlog::error(" Extern certificate has expired. {}.", this->m_subject_name);
        return false;
    }

    // Fix verification, actually all of the certificates are verified while they are being loaded
    // So it sould not be a problem.
    /*
    struct certificate test_ca;
    ak_certificate_opts_create(&test_ca.opts);
    test_ca.vkey = {};

    struct random generator;
    ak_random_create_lcg(&generator);

    ak_asn1 test_asn_1 = ak_certificate_export_to_asn1(this->m_cert_e.get(), UTILS::AkryptManager::getInstance().getCASkey().get(), this->m_cert_ca.get(), &generator);

    if (ak_certificate_import_from_asn1(this->m_cert_e.get(), this->m_cert_ca.get(), test_asn_1) != ak_error_ok)
    {
        spdlog::error(" Signature verification failed {}.", this->m_subject_name);
        ak_certificate_destroy(&test_ca);
        return false;
    }
    ak_certificate_destroy(&test_ca);

    */

    spdlog::info(" Signature verification passed {}.", this->m_subject_name);

    return true;
}

bool Subject::verifyXDiff()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to verify x difference. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    if (std::equal(std::begin(this->m_E_e_point.x), std::end(this->m_E_e_point.x), std::begin(this->m_Q_e_point.x)))
    {
        spdlog::error(" X coordinates are the same. Subject {}.", this->m_subject_name);
        return false;
    }
    spdlog::info(" E_e and Q_e differ. Subject {}.", this->m_subject_name);

    return true;
}

bool Subject::verifyPDiff()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to verify x difference. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    if (std::equal(std::begin(this->m_С_e_point.x), std::end(this->m_С_e_point.x), std::begin(this->m_cert_e.get()->vkey.qpoint.x)))
    {
        spdlog::error(" X coordinates are the same. Subject {}.", this->m_subject_name);
        return false;
    }
    spdlog::info(" C_e and P differ. Subject {}.", this->m_subject_name);

    return true;
}

bool Subject::getIdentifierS()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract self certificate ID. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    std::memcpy(this->m_id_s, ak_tlv_get_string_from_global_name(this->m_cert_s.get()->opts.subject, "2.5.4.3", NULL), this->m_cert_s.get()->opts.subject->len);

    spdlog::info(" Certificate self subject name {}. Subject {}.", this->m_id_s, this->m_subject_name);

    return true;
}

bool Subject::getIdentifierE()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract self certificate ID. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    std::memcpy(this->m_id_e, ak_tlv_get_string_from_global_name(this->m_cert_e.get()->opts.subject, "2.5.4.3", NULL), this->m_cert_e.get()->opts.subject->len);

    spdlog::info(" Certificate self subject name {}. Subject {}.", this->m_id_e, this->m_subject_name);

    return true;
}

bool Subject::generateHValue()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate H value. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    const std::string E_s_string = UTILS::AkryptHelper::makePointsToString(this->m_E_s_point, ak_mpzn256_size);
    const std::string E_e_string = UTILS::AkryptHelper::makePointsToString(this->m_E_e_point, ak_mpzn256_size);

    std::stringstream ss;

    ss << this->m_id_s << E_s_string << this->m_id_e << E_e_string;

    std::memcpy(this->m_H_s, ss.str().c_str(), ss.str().size());
    spdlog::info(" HMAC H value generated {}. Subject {}.", ss.str(), this->m_subject_name);

    return true;
}

bool Subject::generateHMAC()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate HMAC Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    ak_oid streebog_oid;
    ak_pointer streebog_ptr;

    streebog_oid = ak_oid_find_by_name("hmac-streebog512");
    streebog_ptr = ak_oid_new_object(streebog_oid);

    ak_uint8 buffer[128];

    const std::string password = UTILS::AkryptHelper::makePointsToString(this->m_Q_se_point, ak_mpzn256_size);
    const std::string hash = UTILS::AkryptManager::getInstance().getHMACSeed();

    ak_hmac_set_key_from_password((ak_hmac)streebog_ptr, (void*)password.c_str(), password.size(), (void*)hash.c_str(), hash.size());
    std::memset(buffer, 0, sizeof(buffer));

    ak_hmac_ptr((ak_hmac)streebog_ptr, this->m_H_s, sizeof(this->m_H_s), buffer, sizeof(buffer));

    std::string hmac_result = ak_ptr_to_hexstr(buffer, ak_hmac_get_tag_size((ak_hmac)streebog_ptr), ak_false);

    spdlog::info(" HMAC generated {}. Subject {}.", hmac_result, this->m_subject_name);

    std::string X_s_val(hmac_result, 0, 64); 
    std::string Y_s_val(hmac_result, 64, 64); 

    std::memcpy(this->m_X_s, X_s_val.c_str(), X_s_val.size());
    std::memcpy(this->m_Y_s, Y_s_val.c_str(), Y_s_val.size());

    const std::string vba_value = UTILS::AkryptManager::getInstance().getVBAvalue();
    const std::string vab_value = UTILS::AkryptManager::getInstance().getVABvalue();

    std::memcpy(this->m_v_se, vab_value.c_str(), vab_value.size());
    std::memcpy(this->m_v_es, vba_value.c_str(), vba_value.size());

    spdlog::info(" X_s||Y_s||v_e||v_es = {}||{}||{}||{}.", this->m_X_s, this->m_Y_s, this->m_v_se, this->m_v_es);

    return true;
}

// ======================== Class Setters ========================

void Subject::setE_s_point(const wpoint& E_s_point)
{
    this->m_E_s_point = E_s_point;
    spdlog::info(" {} recieved E_s point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_E_s_point, ak_mpzn256_size);
}

void Subject::setE_e_point(const wpoint& E_e_point)
{
    this->m_E_e_point = E_e_point;
    spdlog::info(" {} recieved E_e point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_E_e_point, ak_mpzn256_size);
}

void Subject::setQ_s_point(const wpoint& Q_s_point)
{
    this->m_Q_s_point = Q_s_point;
    spdlog::info(" {} recieved Q_s point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_Q_s_point, ak_mpzn256_size);
}

void Subject::setQ_e_point(const wpoint& Q_e_point)
{
    this->m_Q_e_point = Q_e_point;
    spdlog::info(" {} recieved Q_e point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_Q_e_point, ak_mpzn256_size);
}

void Subject::setС_s_point(const wpoint& С_s_point)
{
    this->m_С_s_point = С_s_point;
    spdlog::info(" {} recieved С_s point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_С_s_point, ak_mpzn256_size);
}

void Subject::setС_e_point(const wpoint& С_e_point)
{
    this->m_С_e_point = С_e_point;
    spdlog::info(" {} recieved С_e point:", this->m_subject_name);
    UTILS::AkryptHelper::logWPoint(this->m_С_e_point, ak_mpzn256_size);
}

void Subject::setN_ca_num(const ak_uint8* ca_serialnum, ak_uint32 ca_serialnum_len)
{
    if (ca_serialnum != nullptr)
    {
        std::memcpy(this->m_ca_serialnum, ca_serialnum, ca_serialnum_len);
        this->m_ca_serialnum_length = ca_serialnum_len;
        spdlog::info(" {} recieved CA cerificate serial number:", this->m_subject_name);
        spdlog::info("     {}", ak_ptr_to_hexstr(this->m_ca_serialnum, ca_serialnum_len, ak_false));
    }
    else
    {
        std::memset(this->m_ca_serialnum, 0, sizeof(this->m_ca_serialnum));
    }
}

void Subject::setN_s_num(const ak_uint8* s_serialnum, ak_uint32 s_serialnum_len)
{
    if (s_serialnum != nullptr)
    {
        std::memcpy(this->m_s_serialnum, s_serialnum, s_serialnum_len);
        this->m_s_serialnum_length = s_serialnum_len;
        spdlog::info(" {} recieved self cerificate serial number:", this->m_subject_name);
        spdlog::info("     {}", ak_ptr_to_hexstr(this->m_s_serialnum, s_serialnum_len, ak_false));
    }
    else
    {
        std::memset(this->m_s_serialnum, 0, sizeof(this->m_s_serialnum));
    }
}

void Subject::setN_e_num(const ak_uint8* e_serialnum, ak_uint32 e_serialnum_len)
{
    if (e_serialnum != nullptr)
    {
        std::memcpy(this->m_e_serialnum, e_serialnum, e_serialnum_len);
        this->m_e_serialnum_length = e_serialnum_len;
        spdlog::info(" {} recieved extern cerificate serial number:", this->m_subject_name);
        spdlog::info("     {}", ak_ptr_to_hexstr(this->m_e_serialnum, e_serialnum_len, ak_false));
    }
    else
    {
        std::memset(this->m_e_serialnum, 0, sizeof(this->m_e_serialnum));
    }
}

void Subject::setReq_s(bool req)
{
    spdlog::info(" {} recieved self cerificate request: {}", this->m_subject_name, (req) ? "true" : "false");
    this->m_req_s = req;
}

void Subject::setReq_e(bool req)
{
    spdlog::info(" {} recieved extern cerificate request: {}", this->m_subject_name, (req) ? "true" : "false");
    this->m_req_e = req;
}

void Subject::set_e_s_id(wcurve_id_t s_wc_id)
{
    spdlog::info(" {} recieved self curve id: {}", this->m_subject_name, std::to_string(static_cast<int>(s_wc_id)));
    this->m_s_wc_id = s_wc_id;
}

void Subject::set_e_e_id(wcurve_id_t e_wc_id)
{
    spdlog::info(" {} recieved extern curve id: {}", this->m_subject_name, std::to_string(static_cast<int>(e_wc_id)));
    this->m_e_wc_id = e_wc_id;
}

void Subject::setCert_s(UTILS::AkryptCertificate cert_s)
{
    this->m_cert_s = cert_s;
}

void Subject::setCert_e(UTILS::AkryptCertificate cert_e)
{
    this->m_cert_e = cert_e;
}

// ======================== Class Getters ========================

const ak_uint64* Subject::getXi_s_key() const
{
    return this->m_Xi_s_key;
}

const ak_uint64* Subject::getXi_e_key() const
{
    return this->m_Xi_e_key;
}

const ak_uint64* Subject::getXi_se_key() const
{
    return this->m_Xi_se_key;
}

const ak_uint64* Subject::getXi_es_key() const
{
    return this->m_Xi_es_key;
}

const wpoint Subject::getE_s_point() const
{
    return this->m_E_s_point;
}

const wpoint Subject::getE_e_point() const
{
    return this->m_E_e_point;
}

const wpoint Subject::getQ_s_point() const
{
    return this->m_Q_s_point;
}

const wpoint Subject::getQ_e_point() const
{
    return this->m_Q_e_point;
}

const ak_uint8* Subject::getN_ca_num() const
{
    return this->m_ca_serialnum;
}

const ak_uint8* Subject::getN_s_num() const
{
    return this->m_s_serialnum;
}

const ak_uint8* Subject::getN_e_num() const
{
    return this->m_e_serialnum;
}

ak_uint32 Subject::getN_ca_num_len() const
{
    return this->m_ca_serialnum_length;
}

ak_uint32 Subject::getN_s_num_len() const
{
    return this->m_s_serialnum_length;
}

ak_uint32 Subject::getN_e_num_len() const
{
    return this->m_e_serialnum_length;
}

bool Subject::getReq_s() const
{
    return this->m_req_s;
}

bool Subject::getReq_e() const
{
    return this->m_req_e;
}

wcurve_id_t Subject::get_e_s_id() const
{
    return this->m_s_wc_id;
}

wcurve_id_t Subject::get_e_e_id() const
{
    return this->m_e_wc_id;
}

UTILS::AkryptCertificate Subject::getCert_s()
{
    return this->m_cert_s;
}

UTILS::AkryptCertificate Subject::getCert_e()
{
    return this->m_cert_e;
}
}
