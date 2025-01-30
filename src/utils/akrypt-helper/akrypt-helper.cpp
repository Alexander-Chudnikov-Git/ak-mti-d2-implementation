#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "akrypt-helper.hpp"

namespace UTILS
{
AkryptCertificate AkryptHelper::loadCertificate(const std::string& certificate_path, AkryptCertificate ca_cert)
{
    UTILS::AkryptManager::getInstance().startUsing();

    if (!UTILS::AkryptManager::getInstance().isInitialized())
    {
        spdlog::error("Libakrypt is not initialized.");
        UTILS::AkryptManager::getInstance().stopUsing();
        return AkryptCertificate();
    }
    spdlog::info(" Started loading certificate.");

    try
    {
        ak_certificate raw_cert = new struct certificate;
        raw_cert->vkey = {};
        raw_cert->opts = {};

        int error = ak_certificate_opts_create(&raw_cert->opts);

        if (error != ak_error_ok)
        {
            spdlog::error("Unable to generate certificate options. {}", getAkErrorDescription(error));
            destroyCertificate(raw_cert);

            UTILS::AkryptManager::getInstance().stopUsing();
            return AkryptCertificate();
        }
        spdlog::info(" Loaded certificate options.");

        if (ca_cert.get() != nullptr && !ca_cert.isCA())
        {
            spdlog::error("Unable to import certificate. {}", getAkErrorDescription(ak_error_certificate_ca));
            destroyCertificate(raw_cert);

            UTILS::AkryptManager::getInstance().stopUsing();
            return AkryptCertificate();
        }

        // There is a small memory leak, wasn't able to fix it, casue it's from akrypt implementation
        error = ak_certificate_import_from_file(raw_cert, ca_cert.get(), certificate_path.c_str());

        if (error != ak_error_ok)
        {
            spdlog::error("Unable to import certificate from file. {}", getAkErrorDescription(error));
            destroyCertificate(raw_cert);

            UTILS::AkryptManager::getInstance().stopUsing();
            return AkryptCertificate();
        }

        spdlog::info(" Certificate {} loaded.", certificate_path);

        AkryptCertificate ak_cert(raw_cert);

        UTILS::AkryptManager::getInstance().stopUsing();
        return ak_cert;

    }
    catch (const std::exception& e)
    {
        spdlog::error("An error occurred: {}", e.what());

        UTILS::AkryptManager::getInstance().stopUsing();
        return AkryptCertificate();
    }
}

void AkryptHelper::destroyCertificate(ak_certificate cert)
{
    if (cert != nullptr)
    {
        ak_certificate_destroy(cert);
        delete cert;
    }
}

AkryptSkey AkryptHelper::loadSkey(const std::string& skey_path)
{
    UTILS::AkryptManager::getInstance().startUsing();

    if (!UTILS::AkryptManager::getInstance().isInitialized())
    {
        spdlog::error("Libakrypt is not initialized.");
        UTILS::AkryptManager::getInstance().stopUsing();
        return AkryptSkey();
    }
    spdlog::info(" Started loading secret key.");

    ak_skey raw_skey = static_cast<ak_skey>(ak_skey_load_from_file(skey_path.c_str()));

    if (raw_skey == nullptr)
    {
        spdlog::error("Failed to load secret key from file. {}", skey_path);
        UTILS::AkryptManager::getInstance().stopUsing();
        ak_skey_delete(raw_skey);
        return AkryptSkey();
    }

    AkryptSkey key(raw_skey);

    UTILS::AkryptManager::getInstance().stopUsing();

    return key;
}

bool AkryptHelper::generateRandomScalar(void* scalar, size_t length)
{
    UTILS::AkryptManager::getInstance().startUsing();

    if (!scalar || length == 0)
    {
        spdlog::error("Invalid scalar buffer or length.");
        return false;
    }

    struct random generator;

    if (ak_random_create_lcg(&generator) != ak_error_ok)
    {
        spdlog::error("Unable to initialize LCG random number generator.");
        return false;
    }

    if (ak_random_ptr(&generator, scalar, length) != ak_error_ok)
    {
        spdlog::error("Failed to generate random values for scalar of length {}.", length);
        ak_random_destroy(&generator);
        return false;
    }

    ak_random_destroy(&generator);

    UTILS::AkryptManager::getInstance().stopUsing();
    return true;
}

void AkryptHelper::logWPoint(struct wpoint& wpoint, const size_t size)
{
    spdlog::info("     x-{}", ak_mpzn_to_hexstr(wpoint.x, size));
    spdlog::info("     y-{}", ak_mpzn_to_hexstr(wpoint.y, size));
    spdlog::info("     z-{}", ak_mpzn_to_hexstr(wpoint.z, size));
}

void AkryptHelper::logStringInBlocks(const std::string& input)
{
    constexpr size_t BLOCK_SIZE = 64;
    size_t totalBlocks = (input.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (size_t i = 0; i < totalBlocks; ++i)
    {
        size_t start = i * BLOCK_SIZE;
        size_t length = std::min(BLOCK_SIZE, input.size() - start);
        spdlog::info("     {}: {}", i + 1, input.substr(start, length));
    }
}

std::string AkryptHelper::makePointsToString(struct wpoint& wpoint, const size_t size)
{
    std::stringstream points_str;

    points_str << ak_mpzn_to_hexstr(wpoint.x, size) << ak_mpzn_to_hexstr(wpoint.y, size) << ak_mpzn_to_hexstr(wpoint.z, size);

    return  points_str.str();
}

std::string_view AkryptHelper::getAkErrorDescription(int error)
{
    switch (error)
    {
        case ak_error_wrong_option:
            return "Attempt to access an undefined library option.";
        case ak_error_invalid_value:
            return "Error using incorrect (unexpected) value.";
        case ak_error_oid_engine:
            return "Incorrect type of cryptographic mechanism.";
        case ak_error_oid_mode:
            return "Incorrect mode of using cryptographic mechanism.";
        case ak_error_oid_name:
            return "Incorrect or undefined name of cryptographic mechanism.";
        case ak_error_oid_id:
            return "Incorrect or undefined identifier of cryptographic mechanism.";
        case ak_error_oid_index:
            return "Incorrect index of identifier of cryptographic mechanism.";
        case ak_error_wrong_oid:
            return "Error accessing oid.";
        case ak_error_curve_not_supported:
            return "Error that occurs when the curve parameters do not match the algorithm in which they are used.";
        case ak_error_curve_point:
            return "Error that occurs if the point does not belong to the given curve.";
        case ak_error_curve_point_order:
            return "Error that occurs when the order of the point is incorrect.";
        case ak_error_curve_discriminant:
            return "Error that occurs if the discriminant of the curve is zero (the equation does not define a curve).";
        case ak_error_curve_order_parameters:
            return "Error that occurs when the auxiliary parameters of the elliptic curve are incorrectly defined.";
        case ak_error_curve_prime_modulo:
            return "Error that occurs when the prime modulus of the curve is set incorrectly.";
        case ak_error_curve_not_equal:
            return "Error that occurs when comparing two elliptic curves.";
        case ak_error_key_value:
            return "Error that occurs when using a key whose value is undefined.";
        case ak_error_key_usage:
            return "Error that occurs when using a key for keyless functions.";
        case ak_error_wrong_block_cipher:
            return "Error that occurs when the fields of the bckey structure are incorrectly filled.";
        case ak_error_wrong_block_cipher_length:
            return "Error that occurs when encrypting/decrypting data whose length is not a multiple of the block length.";
        case ak_error_wrong_key_icode:
            return "Error that occurs when the key integrity code is incorrect.";
        case ak_error_wrong_key_length:
            return "Error that occurs when the key length is incorrect.";
        case ak_error_wrong_key_type:
            return "Error that occurs when using an incorrect key type.";
        case ak_error_low_key_resource:
            return "Error that occurs when there is insufficient key resource.";
        case ak_error_wrong_iv_length:
            return "Error that occurs when using an incorrect length of synchronization vector (initialization vector).";
        case ak_error_wrong_block_cipher_function:
            return "Error that occurs when incorrectly using data encryption/decryption functions.";
        case ak_error_linked_data:
            return "Data agreement error.";
        case ak_error_invalid_asn1_tag:
            return "Using an incorrect value of the field that determines the data type.";
        case ak_error_invalid_asn1_length:
            return "Using an incorrect data length value placed in the ASN1 tree node.";
        case ak_error_invalid_asn1_significance:
            return "Using an incorrect function to read negative data placed in the ASN1 tree node.";
        case ak_error_invalid_asn1_content:
            return "The received ASN.1 data contains incorrect or unexpected content.";
        case ak_error_invalid_asn1_count:
            return "The received ASN.1 data contains an incorrect number of elements.";
        case ak_error_wrong_asn1_encode:
            return "Error that occurs when encoding an ASN1 structure (translation to DER encoding).";
        case ak_error_wrong_asn1_decode:
            return "Error that occurs when decoding an ASN1 structure (translation from DER encoding to an ASN1 structure).";
        case ak_error_certificate_verify_key:
            return "Error using an undefined public key (null pointer) to verify the certificate.";
        case ak_error_certificate_verify_engine:
            return "Error using a public key with an incorrect or unsupported digital signature algorithm to verify the certificate.";
        case ak_error_certificate_verify_names:
            return "Error using a public key to verify the certificate, the extended owner name of which does not match the issuer name in the verified certificate.";
        case ak_error_certificate_validity:
            return "Error when importing/exporting a certificate: the certificate's validity period is not current (expired or has not yet begun).";
        case ak_error_certificate_ca:
            return "Error when importing/exporting a certificate: the certificate is not a CA certificate.";
        case ak_error_certificate_key_usage:
            return "Error when importing a certificate: the certificate does not contain the set bit in the keyUsage extension.";
        case ak_error_certificate_engine:
            return "Error when importing a certificate: the certificate is intended for an incorrect or unsupported digital signature algorithm.";
        case ak_error_certificate_signature:
            return "Error when importing a certificate: the digital signature under the certificate is not valid.";
        case ak_error_signature:
            return "Error when verifying the digital signature under arbitrary data.";
        case ak_error_encrypt_scheme:
            return "Error when choosing an asymmetric encryption scheme.";
        case ak_error_aead_initialization:
            return "Error using an uninitialized aead context.";
        default:
            return "Unknown error code.";
    }
}
}
