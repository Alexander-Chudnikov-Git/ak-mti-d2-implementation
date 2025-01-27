/**
 * @file       <exchanger.hpp>
 * @brief      Заголовочный файл для класса Exchanger
 *
 *             Класс управления процессом обмена ключами.
 *
 * @author     CHOO_IS_FOX (@Alexander-Chudnikov-Git)
 * @date       20.01.2025
 * @version    0.0.1
 *
 * @bug        На данный момент баги отсутствуют.
 *
 * @copyright  А. А. Чудников, Абдуллабеков Т. М, Хохлов E. A. 2025
 *
 * @license    Данный проект находится под публичной лицензией GNUv3.
 *
 */

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
 * @brief      Шаг идентификации субъекта A в протоколе MTI-D2
 *
 *             Выполняет последовательность операций:
 *             1. Извлечение серийного номера субъекта A
 *             2. Установка идентификатора эллиптической кривой для внешнего участника
 *             3. Вычисление точки E_a = ξ_a * P
 *             4. Передачу параметров субъекту B
 *             5. Проверка точки E_b и поиск сертификата
 *
 * @details    Этапы работы:
 *             - enter:   Подготовка параметров субъекта A
 *             - execute: Передача параметров субъекту B
 *             - exit:    Верификация полученных данных
 *
 */
class IdentifySubjectA : public ExchangerStep
{
public:

    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

/**
 * @brief      Шаг запроса и верификации сертификата субъекта A
 *
 *             Выполняет операции:
 *             1. Проверку необходимости запроса сертификата
 *             2. Извлечение серийного номера УЦ от субъекта B
 *             3. Установку параметров кривой для проверки
 *             4. Верификацию 
 *
 * @details    Особенности работы:
 *             - Шаг может быть пропущен, если сертификат уже доступен (m_skip)
 *             - Выполняет проверку целостности по сертификату УЦ
 *
 */
class RequestCertificateA : public ExchangerStep
{
public:

    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;
    
    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;

private:
    bool m_skip = false;///< Если требуется пропустить
};

/**
 * @brief      Шаг обработки сертификата субъекта A
 *
 *             Выполняет полный цикл операций с сертификатом субъекта A:
 *             1. Верификацию и параметров кривой
 *             2. Генерацию ключевых параметров для протокола
 *             3. Вычисление проверочных точек
 *             4. Подготовку к формированию общего секрета
 *
 * @details    Основные этапы:
 *             - enter:   Проверка сертификата и извлечение параметров
 *             - execute: Генерация криптографических параметров и вычисление точек
 *             - exit:    Подготовка к ключеому согласованию (KDF/шифрование)
 *
 * @warning    Для корректной работы требует успешного выполнения предыдущих шагов:
 *             - IdentifySubjectA
 *             - RequestCertificateA
 */
class SubjectCertificateA : public ExchangerStep
{
public:

    bool enter([[maybe_unused]] Subject& subject_a,   [[maybe_unused]] Subject& subject_b) override;
    
    bool execute([[maybe_unused]] Subject& subject_a, [[maybe_unused]] Subject& subject_b) override;

    bool exit([[maybe_unused]] Subject& subject_a,    [[maybe_unused]] Subject& subject_b) override;
};

/**
 * @brief      Шаг идентификации субъекта B [!]
 */
class IdentifySubjectB : public ExchangerStep
{
public:

    bool enter(Subject& subject_a, Subject& subject_b) override;

    bool execute(Subject& subject_a, Subject& subject_b) override;

    bool exit(Subject& subject_a, Subject& subject_b) override;
};

/**
 * @brief      Шаг идентификации субъекта B по сертификату [!]
 */
class IdentifySubjectWithCertificateB : public ExchangerStep
{
public:

    bool enter(Subject& subject_a, Subject& subject_b) override;

    bool execute(Subject& subject_a, Subject& subject_b) override;
    
    bool exit(Subject& subject_a, Subject& subject_b) override;
};


/**
 * @brief      Шаг аутентификации субъекта A [!]
 */
class SubjectAuthenticateA : public ExchangerStep
{
public:
    bool enter(Subject& subject_a, Subject& subject_b) override;

    bool execute(Subject& subject_a, Subject& subject_b) override;

    bool exit(Subject& subject_a, Subject& subject_b) override;
};

/**
 * @brief      Шаг аутентификации субъекта B [!]
 */
class SubjectAuthenticateB : public ExchangerStep
{
public:

    bool enter(Subject& subject_a, Subject& subject_b) override;

    bool execute(Subject& subject_a, Subject& subject_b) override;

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
