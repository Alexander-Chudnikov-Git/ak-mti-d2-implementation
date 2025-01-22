#ifndef EXCHANGER_HPP
#define EXCHANGER_HPP

#include <string>
#include <map>
#include <memory>
#include <functional>

#include "subject.hpp"

namespace MTI_D2
{
/**
 * @brief      Базовый класс для обмена данными
 *
 *             Определяет интерфейс выполнения этапов протокола MTI-D2.
 */
class ExchangerStep
{
public:
    virtual ~ExchangerStep() = default;

    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    virtual bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b)   = 0;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    virtual bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) = 0;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    virtual bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b)    = 0;
};

/**
 * @brief      Шаг идентификации субъекта A
 */
class IdentifySubjectA : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

/**
 * @brief      Шаг запроса сертификата субъекта A
 */
class RequestCertificateA : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;

private:
    bool m_skip = false;///< Если требуется пропустить
};

/**
 * @brief      Шаг обработки сертификата субъекта A
 */
class SubjectCertificateA : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

/**
 * @brief      Шаг идентификации субъекта B
 */
class IdentifySubjectB : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter(Subject& subject_a, Subject& subject_b) override;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute(Subject& subject_a, Subject& subject_b) override;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit(Subject& subject_a, Subject& subject_b) override;
};

/**
 * @brief      Шаг идентификации субъекта B по сертификату
 */
class IdentifySubjectWithCertificateB : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter(Subject& subject_a, Subject& subject_b) override;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute(Subject& subject_a, Subject& subject_b) override;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit(Subject& subject_a, Subject& subject_b) override;
};


/**
 * @brief      Шаг аутентификации субъекта A
 */
class SubjectAuthenticateA : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter(Subject& subject_a, Subject& subject_b) override;
    
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute(Subject& subject_a, Subject& subject_b) override;
    
    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit(Subject& subject_a, Subject& subject_b) override;
};

/**
 * @brief      Шаг аутентификации субъекта B
 */
class SubjectAuthenticateB : public ExchangerStep
{
public:
    /**
     * @brief      Подготовительная фаза
     * @return     true если подготовка успешна
     */
    bool enter(Subject& subject_a, Subject& subject_b) override;
    /**
     * @brief      Основная логика
     * @return     true если шаг выполнен успешно
     */
    bool execute(Subject& subject_a, Subject& subject_b) override;

    /**
     * @brief      Завершающая фаза
     * @return     true если завершение прошло без ошибок
     */
    bool exit(Subject& subject_a, Subject& subject_b) override;
};

/**
 * @brief      Класс управления процессом обмена по протоколу MTI-D2
 *
 *             Обеспечивает:
 *              - Последовательное выполнение шагов протокола
 *              - Управление состоянием участников
 */
class Exchanger
{
public:
    Exchanger();

    /**
     * @brief      Инициализация участников обмена
     * @param[in]  subject_a  Локальный участник
     * @param[in]  subject_b  Внешний участник
     */
    void init(Subject subject_a, Subject subject_b);

    /**
     * @brief      Выполнение полного цикла обмена
     * @return     Кортеж [успех, обновленный subject_a, обновленный subject_b]
     */
    std::tuple<bool, Subject, Subject> perform();

    /**
     * @brief      Сброс состояния к начальному
     */
    void reset();

public:
    /**
     * @brief      Добавление пользовательского шага
     * @param[in]  name  Уникальный идентификатор шага
     * @param[in]  step  Объект шага
     */
    void addStep(const std::string& name, std::shared_ptr<ExchangerStep> step);

    /**
     * @brief      Изменение текущего активного шага
     * @param[in]  name  Идентификатор шага из зарегистрированных
     */
    void changeStep(const std::string& name);

    /**
     * @brief      Переход к следующему шагу в порядке m_step_order
     */
    void nextStep();

private:
    std::map<std::string, std::shared_ptr<ExchangerStep>> m_steps; ///< Реестр доступных шагов
    std::shared_ptr<ExchangerStep>                        m_current_step; ///< Текущий активный шаг
    std::vector<std::string>                              m_step_order; ///< Порядок выполнения шагов
    size_t                                                m_current_index; ///< Индекс текущего шага в m_step_order

    Subject m_subject_a;  ///< Локальный участник обмена
    Subject m_subject_b; ///< Внешний участник обмена
};
}

#endif // EXCHANGER_HPP
