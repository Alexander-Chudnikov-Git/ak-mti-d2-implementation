#ifndef EXCHANGER_HPP
#define EXCHANGER_HPP

#include <string>
#include <map>
#include <memory>
#include <functional>

#include "subject.hpp"

namespace MTI_D2
{
class ExchangerStep
{
public:
    virtual ~ExchangerStep() = default;

    virtual bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b)   = 0;
    virtual bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) = 0;
    virtual bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b)    = 0;
};

class IdentifySubjectA : public ExchangerStep
{
public:
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

class RequestCertificateA : public ExchangerStep
{
public:
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;

private:
    bool m_skip = false;
};

class SubjectCertificateA : public ExchangerStep
{
public:
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

class IdentifySubjectB : public ExchangerStep
{
public:
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;

private:
    bool m_skip = false;
};

class SubjectAuthenticateA : public ExchangerStep
{
public:
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

class SubjectAuthenticateB : public ExchangerStep
{
public:
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

class Exchanger
{
public:
    Exchanger();

    void init(Subject subject_a, Subject subject_b);
    std::tuple<bool, Subject, Subject> perform();
    void reset();

public:
    void addStep(const std::string& name, std::shared_ptr<ExchangerStep> step);
    void changeStep(const std::string& name);
    void nextStep();

private:
    std::map<std::string, std::shared_ptr<ExchangerStep>> m_steps;
    std::shared_ptr<ExchangerStep>                        m_current_step;
    std::vector<std::string>                              m_step_order;
    size_t                                                m_current_index;

    Subject m_subject_a;
    Subject m_subject_b;
};
}

#endif // EXCHANGER_HPP
