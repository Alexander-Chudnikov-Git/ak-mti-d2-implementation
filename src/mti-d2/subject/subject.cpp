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
    // There is a bug with move constructor, that causes double deletion
    // In order to fix it, i should probably implement it, instead of using
    // default one, but i'm too lazy to do it
    //
    // I guess leaking a bit of memory is better then crashes
    /*
    if (this->m_id_s != nullptr)
    {
        delete[] this->m_id_s;
        this->m_id_s = nullptr;
    }

    if (this->m_id_e != nullptr)
    {
        delete[] this->m_id_e;
        this->m_id_e = nullptr;
    }

    if (this->m_H1_s != nullptr)
    {
        delete[] this->m_H1_s;
        this->m_H1_s = nullptr;
    }

    if (this->m_X_s != nullptr)
    {
        delete[] this->m_X_s;
        this->m_X_s = nullptr;
    }

    if (this->m_Y_s != nullptr)
    {
        delete[] this->m_Y_s;
        this->m_Y_s = nullptr;
    }

    if (this->m_v_se != nullptr)
    {
        delete[] this->m_v_se;
        this->m_v_se = nullptr;
    }

    if (this->m_v_es != nullptr)
    {
        delete[] this->m_v_es;
        this->m_v_es = nullptr;
    }

    if (this->m_R_s_text != nullptr)
    {
        delete[] this->m_R_s_text;
        this->m_R_s_text = nullptr;
    }

    if (this->m_R_e_text != nullptr)
    {
        delete[] this->m_R_e_text;
        this->m_R_e_text = nullptr;
    }*/

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


    spdlog::info(" Subject '{}' initialized.", this->m_subject_name);

    this->initLibAkrypt();

    this->m_initialized = true;

    // if id_e is {}
    this->getIdentifierE();
    // else
    /*this->m_id_e = id_e;*/

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
    if (ak_random_ptr(&generator, this->m_Xi_s_key, sizeof(this->m_Xi_s_key) / sizeof(ak_uint64)) != ak_error_ok)
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
    if (ak_random_ptr(&generator, this->m_Xi_se_key, sizeof(this->m_Xi_se_key) / sizeof(ak_uint64)) != ak_error_ok)
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

    ak_wpoint_pow(&temp_point_1, &this->m_С_e_point, this->m_Xi_s_key, sizeof(this->m_Xi_s_key) / sizeof(ak_uint64), this->m_cert_s.get()->vkey.wc);
    ak_wpoint_pow(&temp_point_2, &this->m_С_e_point, reinterpret_cast<ak_uint64 *>(this->m_d_s_key.get()->key), (this->m_d_s_key.get()->key_size / 4), this->m_cert_s.get()->vkey.wc); ///< Yeah, looks painfull
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

    if (this->m_cert_s.get()->opts.subject == nullptr)
    {
        spdlog::error(" Provided certificate has no subject option. Subject {}.", this->m_subject_name);
        return false;
    }

    const char* temp_id_s = reinterpret_cast<char*>(ak_tlv_get_string_from_global_name(this->m_cert_s.get()->opts.subject, "2.5.4.3", NULL));

    if (temp_id_s == nullptr)
    {
        spdlog::error(" Unable to extract self certificate ID. Subject {}.", this->m_subject_name);
        return false;
    }

    if (this->m_id_s)
    {
        delete[] this->m_id_s;
        this->m_id_s = nullptr;
    }

    this->m_id_s = new char[std::strlen(temp_id_s) + 1];
    std::strcpy(this->m_id_s, temp_id_s);

    spdlog::info(" {} Certificate self subject ID:", this->m_subject_name);
    spdlog::info("     {}", this->m_id_s);

    return true;
}

bool Subject::getIdentifierE()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to extract extern certificate ID. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    if (this->m_cert_e.get()->opts.subject == nullptr)
    {
        spdlog::error(" Provided certificate has no subject option. Subject {}.", this->m_subject_name);
        return false;
    }

    const char* temp_id_e = reinterpret_cast<char*>(ak_tlv_get_string_from_global_name(this->m_cert_e.get()->opts.subject, "2.5.4.3", NULL));

    if (temp_id_e == nullptr)
    {
        spdlog::error("Unable to extract extern certificate ID. Subject {}.", this->m_subject_name);
        return false;
    }

    delete[] this->m_id_e;
    this->m_id_e = new char[std::strlen(temp_id_e) + 1];
    std::strcpy(this->m_id_e, temp_id_e);

    spdlog::info(" {} Certificate extern subject ID:", this->m_subject_name);
    spdlog::info("     {}", this->m_id_e);

    return true;
}

bool Subject::generateH1ValueS()
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

    std::string temp = ss.str();
    this->m_H1_s = new char[temp.size() + 1];
    std::strcpy(this->m_H1_s, temp.c_str());

    if (this->m_id_e == nullptr)
    {
        spdlog::error(" Unable to create H value. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" {} H value generated:", this->m_subject_name);
    spdlog::info("     {}", ss.str());

    return true;
}

bool Subject::generateH1ValueE()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate H value. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    const std::string E_s_string = UTILS::AkryptHelper::makePointsToString(this->m_E_s_point, ak_mpzn256_size);
    const std::string E_e_string = UTILS::AkryptHelper::makePointsToString(this->m_E_e_point, ak_mpzn256_size);

    std::stringstream ss;

    ss << this->m_id_e << E_e_string << this->m_id_s << E_s_string ;

    std::string temp = ss.str();
    this->m_H1_s = new char[temp.size() + 1];
    std::strcpy(this->m_H1_s, temp.c_str());

    if (this->m_id_e == nullptr)
    {
        spdlog::error(" Unable to create H value. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" {} H value generated:", this->m_subject_name);
    spdlog::info("     {}", ss.str());

    return true;
}

bool Subject::generateH2ValueS()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate H2 value. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    const std::string Xi_s_string  = ak_mpzn_to_hexstr(this->m_Xi_se_key, ak_mpzn256_size);
    const std::string P_s_string   = ak_mpzn_to_hexstr(this->m_P_s_text, ak_mpzn256_size);

    std::stringstream ss;

    ss << this->m_H1_s << Xi_s_string << P_s_string;

    std::string temp = ss.str();
    this->m_H2_s = new char[temp.size() + 1];
    std::strcpy(this->m_H2_s, temp.c_str());

    if (this->m_id_e == nullptr)
    {
        spdlog::error(" Unable to create H2 value. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" {} H2 value generated:", this->m_subject_name);
    spdlog::info("     {}", ss.str());

    return true;
}

bool Subject::generateH2ValueE()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate H2 value. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    const std::string Xi_e_string  = ak_mpzn_to_hexstr(this->m_Xi_se_key, ak_mpzn256_size);
    const std::string P_s_string   = ak_mpzn_to_hexstr(this->m_P_s_text, ak_mpzn256_size);

    std::stringstream ss;

    ss << this->m_H1_s << P_s_string << Xi_e_string;

    std::string temp = ss.str();
    this->m_H2_s = new char[temp.size() + 1];
    std::strcpy(this->m_H2_s, temp.c_str());

    if (this->m_id_e == nullptr)
    {
        spdlog::error(" Unable to create H2 value. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" {} H2 value generated:", this->m_subject_name);
    spdlog::info("     {}", ss.str());

    return true;
}

bool Subject::generateHMAC()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate HMAC. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    ak_oid streebog_oid;
    ak_pointer streebog_ptr;

    streebog_oid = ak_oid_find_by_name("hmac-streebog512");
    streebog_ptr = ak_oid_new_object(streebog_oid);

    ak_uint8 buffer[64];
    std::memset(buffer, 0, sizeof(buffer) / sizeof(ak_uint8));

    const std::string password = UTILS::AkryptHelper::makePointsToString(this->m_Q_se_point, ak_mpzn256_size);
    const std::string hash = UTILS::AkryptManager::getInstance().getHMACSeed();

    ak_hmac_set_key_from_password((ak_hmac)streebog_ptr, (void*)password.c_str(), password.size(), (void*)hash.c_str(), hash.size());
    //k_hmac_set_key_from_password((ak_hmac)streebog_ptr, (void*)buffer, 128, (void*)hash.c_str(), hash.size()); // DEBUG

    ak_hmac_ptr((ak_hmac)streebog_ptr, this->m_H1_s, std::strlen(this->m_H1_s), buffer, sizeof(buffer) / sizeof(ak_uint8));

    std::string hmac_result = ak_ptr_to_hexstr(buffer, ak_hmac_get_tag_size((ak_hmac)streebog_ptr), ak_false);

    spdlog::info(" {} HMAC generated:", this->m_subject_name);
    spdlog::info("     {}", hmac_result);

    std::string X_s_val = hmac_result.substr(0, 64);
    std::string Y_s_val = hmac_result.substr(64, 64);

    delete[] this->m_X_s;
    this->m_X_s = new char[X_s_val.size() + 1];
    std::strcpy(this->m_X_s, X_s_val.c_str());

    delete[] this->m_Y_s;
    this->m_Y_s = new char[Y_s_val.size() + 1];
    std::strcpy(this->m_Y_s, Y_s_val.c_str());

    const std::string vba_value = UTILS::AkryptManager::getInstance().getVBAvalue();
    const std::string vab_value = UTILS::AkryptManager::getInstance().getVABvalue();

    delete[] this->m_v_se;
    this->m_v_se = new char[vab_value.size() + 1];
    std::strcpy(this->m_v_se, vab_value.c_str());

    delete[] this->m_v_es;
    this->m_v_es = new char[vba_value.size() + 1];
    std::strcpy(this->m_v_es, vba_value.c_str());

    spdlog::info("     X_s  = {}", this->m_X_s);
    spdlog::info("     Y_s  = {}", this->m_Y_s);
    spdlog::info("     v_se = {}", this->m_v_se);
    spdlog::info("     v_es = {}", this->m_v_es);

    ak_hmac_destroy((ak_hmac)streebog_ptr);

    return true;
}

bool Subject::Subject::generateMAConA()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate MAC Xi_se. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    struct bckey mac_key;

    int error = ak_error_ok;

    error = ak_bckey_create_kuznechik(&mac_key);
    if (error != ak_error_ok)
    {
        spdlog::error(" Failed to make MAC. Oid create error! {} | {}", error, this->m_subject_name);
        return false;
    }

    // strange cuz in m_H2_s we take this->m_H1_s as first not m_id_s
    // see that shit: (not working idk, but there is my opinion...)
    // ==============
    /*spdlog::error(" Step 1!");
    std::string Xi_e_string  = ak_mpzn_to_hexstr(this->m_Xi_se_key, ak_mpzn256_size);
    std::string P_s_string   = ak_mpzn_to_hexstr(this->m_P_s_text, ak_mpzn256_size);
    spdlog::error(" Step 2!");

    std::stringstream ss;

    //Cortage from ID_a || P_a || Xi_ab = m_id_s + m_P_s_text + m_Xi_se_key
    ss << this->m_H1_s << P_s_string << Xi_e_string; // here wtf, not like in file


    char* dummy = {nullptr};

    std::string temp = ss.str();
    dummy = new char[temp.size() + 1];
    std::strcpy(dummy, temp.c_str());

    spdlog::error(" Step 3!");
    */
    // end =========

    // maybe not working fine as planned. this->m_H2_s doesnt work. due to info from net mac uses secret self key
    // all stuff or not working (unknown errors like -2 -4 -7) or not compile...
    // took CA to ez verify        // here is why MAC's are same (math problem)
    error = ak_bckey_set_key(&mac_key, this->m_ca_serialnum, sizeof(this->m_ca_serialnum)); // Cortage from? ID_a || P_a || Xi_ab = m_H1_s + m_P_s_text + m_Xi_se_key
    if (error != ak_error_ok)
    {
        spdlog::error(" Failed to set key in MAC. {} | {}", error, this->m_subject_name);
        return false;
    }

    // here m_T_a_mac as T_a in step 14.
                        //struct // data to chiper //sz //imito //bkey sz
    error = ak_bckey_cmac(&mac_key, this->m_Y_s, sizeof(this->m_Y_s), m_T_a_mac, mac_key.bsize);
    if (error  != ak_error_ok)
    {
        spdlog::error(" Failed to make MAC. {} | {}", error, this->m_subject_name);
        return false;
    } 

    // set to info when checked mac
    spdlog::error(" Created MAC: {} | {}", ak_ptr_to_hexstr( m_T_a_mac, mac_key.bsize, ak_false ), this->m_subject_name);

    return true;
}

bool Subject::generateMAConB()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate MAC Xi_se. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    struct bckey mac_key;

    int error = ak_error_ok;

    error = ak_bckey_create_kuznechik(&mac_key);
    if (error != ak_error_ok)
    {
        spdlog::error(" Failed to make MAC. Oid create error! {} | {}", error, this->m_subject_name);
        return false;
    }

    // problem see upper
    // took CA to ez verify
    error = ak_bckey_set_key(&mac_key, this->m_ca_serialnum, sizeof(this->m_ca_serialnum)); // Cortage from? ID_a || P_a || Xi_ab = m_H1_s + m_P_s_text + m_Xi_se_key
    if (error != ak_error_ok)
    {
        spdlog::error(" Failed to set key in MAC. {} | {}", error, this->m_subject_name);
        return false;
    }

    // here m_T_b_mac as T_b in step 14.
                        //struct // data to chiper //sz //imito //bkey sz
    error = ak_bckey_cmac(&mac_key, this->m_Y_s, sizeof(this->m_Y_s), m_T_b_mac, mac_key.bsize);
    if (error  != ak_error_ok)
    {
        spdlog::error(" Failed to make MAC. {} | {}", error, this->m_subject_name);
        return false;
    } 

    // set to info when checked mac
    spdlog::error(" Created MAC: {} | {}", ak_ptr_to_hexstr( m_T_b_mac, mac_key.bsize, ak_false ), this->m_subject_name);

    return true;
}

bool Subject::checkMAConB()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to Check MAC. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    // Not all stuff is in the code, sadly, or i missed smth
    //m_X_s, m_id_s || m_Xi_es_key || m_P_e_text 

    /*std::stringstream ss;

    ss << this->m_id_s << m_Xi_es_key << m_P_e_text; 

    std::string temp = ss.str();
    this->m_H2_s = new char[temp.size() + 1];
    std::strcpy(this->m_H2_s, temp.c_str());*/

    return true;
}

bool Subject::checkMAConA()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to Check MAC. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    // m_Y_s, m_id_e || m_Xi_se_key || m_P_s_text

    //std::stringstream ss;

    //ss << this->m_id_e << this->m_Xi_se_key << this->m_P_s_text; 

    //std::string temp = ss.str();
    //char* computed_data = new char[temp.size() + 1];
    //std::strcpy(this->m_H2_s, temp.c_str());
    return true;
}

ak_uint8* Subject::getMAC_on_B()
{
    return m_T_b_mac;
}

ak_uint8* Subject::getMAC_on_A()
{
    return m_T_a_mac;
}

bool Subject::encryptXivalue()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to encrypt Xi_se. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    struct bckey kuznechik_key;
    ak_uint8 iv[16] = {0};

    auto vb_value = UTILS::AkryptManager::getInstance().getVBAvalue();

    std::memcpy(iv, vb_value.data(), std::min(vb_value.size(), sizeof(iv) / sizeof(ak_uint8)));

    if (ak_bckey_create_kuznechik(&kuznechik_key) != ak_error_ok)
    {
        spdlog::error(" Unable to create kuznechik bckey. Subject {}.", this->m_subject_name);
        return false;
    }

    if (ak_bckey_set_key(&kuznechik_key, this->m_X_s, 32) != ak_error_ok)
    {
        spdlog::error(" Unable to set kuznechik key. Subject {}.", this->m_subject_name);
        return false;
    }

    delete[] this->m_R_s_text;
    this->m_R_s_text = new ak_uint64[sizeof(this->m_Xi_se_key) / sizeof(ak_uint64)];

    if (ak_bckey_ctr(&kuznechik_key, this->m_Xi_se_key, this->m_R_s_text, sizeof(this->m_Xi_se_key) / sizeof(ak_uint64), iv, sizeof(iv) / sizeof(ak_uint8)) != ak_error_ok)
    {
        spdlog::error(" Unable to encrypt Xi_se. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" {} Xi_se enctypted:", this->m_subject_name);
    spdlog::info("     Xi_se = {}", ak_mpzn_to_hexstr(this->m_Xi_se_key, ak_mpzn256_size));
    spdlog::info("     R_s   = {}", ak_mpzn_to_hexstr(this->m_R_s_text, ak_mpzn256_size));

    return true;
}

bool Subject::decryptXivalue()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to decrypt Xi_se. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    struct bckey kuznechik_key;
    ak_uint8 iv[16] = {0};

    auto vb_value = UTILS::AkryptManager::getInstance().getVBAvalue();

    std::memcpy(iv, vb_value.data(), std::min(vb_value.size(), sizeof(iv) / sizeof(ak_uint8)));

    if (ak_bckey_create_kuznechik(&kuznechik_key) != ak_error_ok)
    {
        spdlog::error(" Unable to create kuznechik bckey. Subject {}.", this->m_subject_name);
        return false;
    }

    if (ak_bckey_set_key(&kuznechik_key, this->m_X_s, 32) != ak_error_ok)
    {
        spdlog::error(" Unable to set kuznechik key. Subject {}.", this->m_subject_name);
        return false;
    }

    if (m_R_e_text == nullptr)
    {
        spdlog::error(" R_e is not provided. Subject {}.", this->m_subject_name);
        return false;
    }

    delete[] this->m_P_s_text;
    this->m_P_s_text = new ak_uint64[32];
    //this->m_P_s_text = new ak_uint64[sizeof(this->m_R_e_text) / sizeof(ak_uint64)];

    //if (ak_bckey_ctr(&kuznechik_key, this->m_R_e_text, this->m_P_s_text, sizeof(this->m_R_e_text) / sizeof(ak_uint64), iv, sizeof(iv) / sizeof(ak_uint8)) != ak_error_ok)
    if (ak_bckey_ctr(&kuznechik_key, this->m_R_e_text, this->m_P_s_text, 32, iv, sizeof(iv) / sizeof(ak_uint8)) != ak_error_ok)
    {
        spdlog::error(" Unable to decrypt Xi_se. Subject {}.", this->m_subject_name);
        return false;
    }

    spdlog::info(" {} Xi_se dectypted:", this->m_subject_name);
    spdlog::info("     P_s = {}", ak_mpzn_to_hexstr(this->m_P_s_text, ak_mpzn256_size));
    spdlog::info("     R_e = {}", ak_mpzn_to_hexstr(this->m_R_e_text, ak_mpzn256_size));

    return true;
}

bool Subject::generateKkey()
{
    if (!this->m_initialized)
    {
        spdlog::error(" Unable to generate K key. Subject {} is not initialized.", this->m_subject_name);
        return false;
    }

    ak_oid streebog_oid;
    ak_pointer streebog_ptr;

    streebog_oid = ak_oid_find_by_name("hmac-streebog512");
    streebog_ptr = ak_oid_new_object(streebog_oid);

    ak_uint8 buffer[64];
    std::memset(buffer, 0, sizeof(buffer) / sizeof(ak_uint8));

    const std::string password = UTILS::AkryptHelper::makePointsToString(this->m_Q_se_point, ak_mpzn256_size);
    const std::string hash = UTILS::AkryptManager::getInstance().getHMACSeed();

    ak_hmac_set_key_from_password((ak_hmac)streebog_ptr, (void*)password.c_str(), password.size(), (void*)hash.c_str(), hash.size());

    ak_hmac_ptr((ak_hmac)streebog_ptr, this->m_H2_s, std::strlen(this->m_H2_s), buffer, sizeof(buffer) / sizeof(ak_uint8));

    std::string k_key_result = ak_ptr_to_hexstr(buffer, ak_hmac_get_tag_size((ak_hmac)streebog_ptr), ak_false);

    spdlog::info(" {} K key generated:", this->m_subject_name);
    spdlog::info("     {}", k_key_result);

    if (sizeof(buffer) % sizeof(ak_uint64) != 0)
    {
        spdlog::error(" K key buffer size is not a multiple of ak_uint64 size for Subject {}.", this->m_subject_name);
        ak_hmac_destroy((ak_hmac)streebog_ptr);
        return false;

    }

    std::memcpy(this->m_K_se_key, buffer, sizeof(buffer) / sizeof(ak_uint8));

    ak_hmac_destroy((ak_hmac)streebog_ptr);

    return true;
}

// ======================== Class Setters ========================

void Subject::setR_s_text(const ak_uint64* r_s_text, ak_uint32 r_s_text_len)
{
    delete[] this->m_R_s_text;
    this->m_R_s_text = new ak_uint64[r_s_text_len];
    std::copy(r_s_text, r_s_text + r_s_text_len, this->m_R_s_text);

    spdlog::info(" {} recieved R_s text:", this->m_subject_name);
    spdlog::info("     R_s   = {}", ak_mpzn_to_hexstr(this->m_R_s_text, ak_mpzn256_size));
}

void Subject::setR_e_text(const ak_uint64* r_e_text, ak_uint32 r_e_text_len)
{
    delete[] this->m_R_e_text;
    this->m_R_e_text = new ak_uint64[r_e_text_len];
    std::copy(r_e_text, r_e_text + r_e_text_len, this->m_R_e_text);

    spdlog::info(" {} recieved R_e text:", this->m_subject_name);
    spdlog::info("     R_e   = {}", ak_mpzn_to_hexstr(this->m_R_e_text, ak_mpzn256_size));
}

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
        std::memset(this->m_ca_serialnum, 0, sizeof(this->m_ca_serialnum) / sizeof(ak_uint8));
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
        std::memset(this->m_s_serialnum, 0, sizeof(this->m_s_serialnum) / sizeof(ak_uint8));
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
        std::memset(this->m_e_serialnum, 0, sizeof(this->m_e_serialnum) / sizeof(ak_uint8));
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
    spdlog::info(" {} recieved self sertificate", this->m_subject_name);

    this->m_cert_s = cert_s;
}

void Subject::setCert_e(UTILS::AkryptCertificate cert_e)
{
    spdlog::info(" {} recieved etern sertificate", this->m_subject_name);

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

const ak_uint64* Subject::getR_s_text() const
{
    return this->m_R_s_text;
}

const ak_uint64* Subject::getR_e_text() const
{
    return this->m_R_e_text;
}

const ak_uint64* Subject::getK_s_key() const
{
    return this->m_K_se_key;
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

char* Subject::getIdS() const
{
    if (!m_id_s)
    {
        return nullptr;
    }

    size_t len = std::strlen(m_id_s) + 1;
    char* copy = new char[len];
    std::strcpy(copy, m_id_s);
    return copy;
}

char* Subject::getIdE() const
{
    if (!m_id_e)
    {
        return nullptr;
    }

    size_t len = std::strlen(m_id_e) + 1;
    char* copy = new char[len];
    std::strcpy(copy, m_id_e);
    return copy;
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
