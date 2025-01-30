#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "exchanger.hpp"
#include "option-parser.hpp"
#include "akrypt-manager.hpp"
#include "akrypt-helper.hpp"
#include "subject.hpp"

int main(const int argc, const char** argv)
{
    auto option_parser = UTILS::OptionParser(PROJECT_NAME, "This program is proof-of-concept implementation of MTI-D2 key exchange protocol.");

    option_parser.addOption("h,help",  "Prints help menu.");
    option_parser.addOption("d,debug", "Prints debug info.");

    option_parser.addOption<std::string>("c,cert-ca", "Path to the certificate authority file.");
    option_parser.addOption<std::string>("a,cert-a",  "Path to the subject's A certificate file.");
    option_parser.addOption<std::string>("b,cert-b",  "Path to the subject's B certificate file.");
    option_parser.addOption<std::string>("C,key-ca",  "Path to the certificate authority secret key.");
    option_parser.addOption<std::string>("A,key-a",   "Path to the subject's A secret key.");
    option_parser.addOption<std::string>("B,key-b",   "Path to the subject's B secret key.");

    option_parser.parseOptions(argc, argv);

    if (option_parser.hasOption("h"))
    {
        option_parser.logHelp();
    }

    if (option_parser.hasOption("d"))
    {
        option_parser.debugLog(argc, argv);
    }

    if (!option_parser.hasOption("c"))
    {
        spdlog::error(" CA cert is required for this application to work.");
        option_parser.logHelp();
        exit(2);
    }

    auto ca_cert = UTILS::AkryptHelper::loadCertificate(option_parser.getOption("c"));

    if (!ca_cert.isInitialized())
    {
        exit(2);
    }

    /*
    if (!option_parser.hasOption("C"))
    {
        spdlog::error(" CA key is required for this application to work.");
        option_parser.logHelp();
        exit(2);
    }

    auto ca_key = UTILS::AkryptHelper::loadSkey(option_parser.getOption("C"));
    UTILS::AkryptManager::getInstance().setCASkey(ca_key);
    */

    if (!option_parser.hasOption("a"))
    {
        spdlog::error(" Subject A certificate is required for this application to work.");
        option_parser.logHelp();
        exit(2);
    }

    auto a_cert = UTILS::AkryptHelper::loadCertificate(option_parser.getOption("a"), ca_cert);

    if (!a_cert.isInitialized())
    {
        exit(2);
    }

    if (!option_parser.hasOption("A"))
    {
        spdlog::error(" Subject A secret key is required for this application to work.");
        option_parser.logHelp();
        exit(2);
    }

    auto a_key = UTILS::AkryptHelper::loadSkey(option_parser.getOption("A"));

    if (!a_key.isInitialized())
    {
        exit(2);
    }

    if (!option_parser.hasOption("b"))
    {
        spdlog::error(" Subject B certificate is required for this application to work.");
        option_parser.logHelp();
        exit(2);
    }

    auto b_cert = UTILS::AkryptHelper::loadCertificate(option_parser.getOption("b"), ca_cert);

    if (!b_cert.isInitialized())
    {
        exit(2);
    }

    if (!option_parser.hasOption("B"))
    {
        spdlog::error(" Subject B secret key is required for this application to work.");
        option_parser.logHelp();
        exit(2);
    }

    auto b_key = UTILS::AkryptHelper::loadSkey(option_parser.getOption("B"));

    if (!b_key.isInitialized())
    {
        exit(2);
    }

    auto a_subject = MTI_D2::Subject("Subject A", ca_cert, a_cert, a_key, b_cert);
    auto b_subject = MTI_D2::Subject("Subject B", ca_cert, b_cert, b_key, a_cert);

    UTILS::AkryptManager::getInstance().setHMACSeed("random_hmac_seed");

    // Must be 16 symbols
    std::string uv_value16 = "random_uv_value_";
    UTILS::AkryptManager::getInstance().setUVvalue(uv_value16);

    auto exchanger = MTI_D2::Exchanger();

    exchanger.init(a_subject, b_subject);
    exchanger.perform();

	return 0;
}
