#include "option-parser.hpp"

namespace UTILS
{
OptionParser::OptionParser(const std::string& app_name, const std::string& app_description) :
    m_options(std::make_unique<cxxopts::Options>(app_name, app_description))
{
    this->m_options->allow_unrecognised_options();
    return;
}

OptionParser::~OptionParser()
{
    this->m_options.reset();
    this->m_parsed_options.reset();

    return;
}


void OptionParser::parseOptions(const int argc, const char** argv)
{
    if (!this->m_options)
    {
        spdlog::error(" Unable to parse options, Option Parser is not initialized.");
    }

    try
    {
        this->m_parsed_options = std::make_unique<cxxopts::ParseResult>(this->m_options->parse(argc, argv));

        for (const auto& unmatched_argument: this->m_parsed_options->unmatched())
        {
            spdlog::warn(" Unsupported argument passed: {}", unmatched_argument);
        }

        return;
    }
    catch (const cxxopts::exceptions::exception& e)
    {
        spdlog::error(" Error parsing command line options: {}", e.what());
    }
    catch (...)
    {
        spdlog::error(" Unknown error occurred while parsing arguments.");
    }

    exit(1);
}

bool OptionParser::hasOption(const std::string& name) const
{
    if (!this->m_parsed_options)
    {
        spdlog::error(" Options have not been parsed yet. Call parseOptions() first.");
        return false;
    }

    return this->m_parsed_options->count(name) > 0;
}

void OptionParser::addOption(const std::string& name, const std::string& description)
{
    if (!this->m_options)
    {
        spdlog::error(" Unable to add option, Option Parser is not initialized.");
        return;
    }

    this->m_options->add_options()(name, description);

    return;
}

size_t OptionParser::getOptionCount(const std::string& name) const
{
    if (!this->m_parsed_options)
    {
        spdlog::error(" Options have not been parsed yet. Call parseOptions() first.");
        return 0;
    }

    return this->m_parsed_options->count(name);
}

void OptionParser::logHelp() const
{
    if (!this->m_options)
    {
        spdlog::error(" Unable to get help message, Option Parser is not initialized.");
        return;
    }

    std::string help_message = this->m_options->help();
    std::istringstream iss(help_message);
    std::string line;

    while (std::getline(iss, line))
    {
        spdlog::info(" {}", line);
    }
}

void OptionParser::debugLog(const int argc, const char** argv) const
{
    spdlog::info("===========================================================");
    spdlog::info(" Project Information");
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Project Name: {:<24} {}", PROJECT_NAME, PROJECT_VERSION);
    spdlog::info(" Compile Time: {}", COMPILE_TIME);
    spdlog::info(" Compiler:     {:<24} {}", COMPILER_ID, COMPILER_VERSION);
    spdlog::info("===========================================================");
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Command-Line Arguments");
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Argument Count: {}", argc);
    for (int i = 0; i < argc; ++i) {
        spdlog::info(" Argument [{}]: {}", i, argv[i]);
    }
    spdlog::info("===========================================================");
}
}
