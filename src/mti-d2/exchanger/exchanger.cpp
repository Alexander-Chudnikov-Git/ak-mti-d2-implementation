#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include "exchanger.hpp"

namespace MTI_D2
{

// ================ IdentifySubjectA ================

bool IdentifySubjectA::enter([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    spdlog::info("-----------------------------------------------------------");

    if (!subject_a.extractSerialNumber())
    {
        return false;
    }

    if (!subject_a.generateRandomXiScalar())
    {
        return false;
    }

    if (!subject_a.calculateEPoint())
    {
        return false;
    }

    return true;
}

bool IdentifySubjectA::execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    spdlog::info("                                                           ");

    ak_uint8 serialnum[32] = {0};
    auto serialnum_len = subject_a.getN_s_num_len();

    if (serialnum_len > sizeof(serialnum))
    {
        return false;
    }

    subject_b.setReq_e(subject_a.getReq_s());
    subject_b.setN_e_num(subject_a.getN_s_num(), serialnum_len);
    subject_b.setE_e_point(subject_a.getE_s_point());

    spdlog::info("                                                           ");

    return true;
}

bool IdentifySubjectA::exit([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    if (!subject_b.checkExternEPoint())
    {
        return false;
    }

    if (!subject_b.findExternCert())
    {
        return false;
    }

    spdlog::info("-----------------------------------------------------------");

    return true;
}

// ================ RequestCertificateA ================

bool RequestCertificateA::enter([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    spdlog::info("-----------------------------------------------------------");

    this->m_skip = !subject_b.getReq_s();

    if (this->m_skip)
    {
        return true;
    }

    if (!subject_b.extractCASerialNumber())
    {
        return false;
    }

    ak_uint8 serialnum[32] = {0};
    auto serialnum_len = subject_b.getN_ca_num_len();

    if (serialnum_len > sizeof(serialnum))
    {
        return false;
    }

    subject_a.setN_ca_num(subject_b.getN_ca_num(), serialnum_len);
    subject_a.set_e_e_id(subject_b.get_e_s_id());


    return true;
}

bool RequestCertificateA::execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    if (this->m_skip)
    {
        spdlog::info(" Certificate already exists, skipping step.");
        return true;
    }

    spdlog::info("                                                           ");

    if (subject_a.verifyCaSerialNumber())
    {
        return false;
    }

    if (subject_a.verifyWCType())
    {
        return false;
    }

    spdlog::info("                                                           ");

    return true;
}

bool RequestCertificateA::exit([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    if (this->m_skip)
    {
        spdlog::info("-----------------------------------------------------------");
        return true;
    }

    subject_b.setCert_e(subject_a.getCert_s());

    spdlog::info("-----------------------------------------------------------");

    return true;
}

// ================ SubjectCertificateA ================

bool SubjectCertificateA::enter([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    spdlog::info("-----------------------------------------------------------");

    if (!subject_b.verifyExternCa())
    {
        return false;
    }

    if (!subject_b.extractExternCertId())
    {
        return false;
    }

    if (!subject_b.extractExternPublicKey())
    {
        return false;
    }

    if (!subject_b.verifyXDiff())
    {
        return false;
    }

    return true;
}

bool SubjectCertificateA::execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{
    spdlog::info("                                                           ");

    if (!subject_b.generateRandomXiScalar())
    {
        return false;
    }

    if (!subject_b.calculateEPoint())
    {
        return false;
    }

    if (!subject_b.calculateСPoint())
    {
        return false;
    }

    if (!subject_b.verifyPDiff())
    {
        return false;
    }

    if (!subject_b.calculateQPoint())
    {
        return false;
    }

    spdlog::info("                                                           ");

    return true;
}

bool SubjectCertificateA::exit([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b)
{

    if (!subject_b.generateRandomXiSEScalar())
    {
        return false;
    }

    ///< Implement kdf and enc here

    spdlog::info("-----------------------------------------------------------");

    return true;
}



// ================ Exchanger ================

Exchanger::Exchanger()
{
}

void Exchanger::init(Subject subject_a, Subject subject_b)
{
    spdlog::info("===========================================================");
    spdlog::info(" Starting state machine initialization.");
    spdlog::info("-----------------------------------------------------------");

    this->m_subject_a = subject_a;
    this->m_subject_b = subject_b;

    this->addStep("IdentifySubjectA",    std::make_unique<IdentifySubjectA>());
    this->addStep("RequestCertificateA", std::make_unique<RequestCertificateA>());
    this->addStep("SubjectCertificateA", std::make_unique<SubjectCertificateA>());

    //this->addStep("IdentifySubjectB", std::make_unique<IdentifySubjectB>());
    //this->addStep("IdentifySubjectWithCertificateB", std::make_unique<IdentifySubjectWithCertificateB>());
    //this->addStep("SubjectAuthenticateA", std::make_unique<SubjectAuthenticateA>());
    //this->addStep("SubjectAuthenticateB", std::make_unique<SubjectAuthenticateB>());

    this->reset();

    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" State machine initialized.");
    spdlog::info("===========================================================");
}

std::tuple<bool, Subject, Subject> Exchanger::perform()
{
    bool status = true;

    spdlog::info(" Starting state machine.");
    while (this->m_current_step)
    {
        status = this->m_current_step->enter(m_subject_a, m_subject_b);

        if (!status)
        {
            spdlog::info("-----------------------------------------------------------");
            spdlog::error(" Error occurred during enter phase of this step.");
            break;
        }

        status = this->m_current_step->execute(m_subject_a, m_subject_b);

        if (!status)
        {
            spdlog::info("-----------------------------------------------------------");
            spdlog::error(" Error occurred during execute phase of this step.");
            break;
        }

        status = this->m_current_step->exit(m_subject_a, m_subject_b);

        if (!status)
        {
            spdlog::info("-----------------------------------------------------------");
            spdlog::error(" Error occurred during exit phase of this step.");
            break;
        }

        this->nextStep();
    }

    this->reset();

    return std::make_tuple(status, m_subject_a, m_subject_b);
}

void Exchanger::reset()
{
    this->m_current_index = 0;

    if (!m_step_order.empty())
    {
        this->m_current_step = (this->m_steps[this->m_step_order[this->m_current_index]]);
    }
    else
    {
        this->m_current_step = nullptr;
    }
}

void Exchanger::addStep(const std::string& name, std::shared_ptr<ExchangerStep> step)
{
    this->m_steps[name] = (step);
    this->m_step_order.push_back(name);

    if (this->m_step_order.size() == 1)
    {
        this->m_current_step = (this->m_steps[name]);
    }
    spdlog::info(" {} - State machine step added {}.", this->m_step_order.size(), name);
}

void Exchanger::changeStep(const std::string& name)
{
    if (this->m_steps.count(name))
    {
        this->m_current_step = (this->m_steps[name]);

        for (size_t i = 0; i < this->m_step_order.size(); ++i)
        {
            if (this->m_step_order[i] == name)
            {
                this->m_current_index = i;
                break;
            }
        }

        spdlog::info(" Switching to the step {}.", name);
    }
    else
    {
        this->m_current_step = nullptr;

        spdlog::warn(" Unable no switch to step {}. There is no such step.", name);
    }
}

void Exchanger::nextStep()
{
    if (this->m_current_index < this->m_step_order.size() - 1)
    {
        this->m_current_index++;
        this->m_current_step = (this->m_steps[this->m_step_order[this->m_current_index]]);
        spdlog::info(" Switching to the next step {}.", this->m_step_order[this->m_current_index]);
    }
    else
    {
        this->m_current_step = nullptr;
        spdlog::info(" No steps left, stopping state machine.");
    }
}
}
