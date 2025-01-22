#ifndef OPTION_PARSER_HPP
#define OPTION_PARSER_HPP

#include <cxxopts.hpp> ///< Библиотека для парсинга параметров командной строки
#include <memory>
#include <string>
#include <type_traits>

#include <spdlog/spdlog.h> ///< Библиотека для вывода логов в командной строке
#include <spdlog/sinks/stdout_color_sinks.h> ///< Цветной вывод данных

namespace UTILS
{
/**
 * @brief      Класс обработки параметров командной строки
 *     
 */
class OptionParser
{
public:
    /**
     * @brief      Конструктор парсера опций
     * 
     * @param[in]  app_name         Название приложения для вывода в справке
     * @param[in]  app_description  Описание приложения для вывода в справке
     */
    OptionParser(const std::string& app_name, const std::string& app_description);
    
    /**
     * @brief Деструктор (генерируется по умолчанию)
     */
    ~OptionParser();

    /**
     * @brief      Парсинг аргументов командной строки
     * 
     * @param[in]  argc  Количество аргументов
     * @param[in]  argv  Массив строк аргументов
     * @throws     cxxopts::exceptions::exception В случае ошибок парсинга
     * 
     * @note Должен вызываться после добавления всех опций через addOption()
     */
    void parseOptions(const int argc, const char** argv);

    /**
     * @brief      Проверка наличия опции
     * 
     * @param[in]  name  Имя опции
     * @return     true если опция присутствует в аргументах
     */
    bool hasOption(const std::string& name) const;

    /**
     * @brief      Добавление флага (опции без значения)
     * 
     * @param[in]  name         Имя опции
     * @param[in]  description  Описание для справки
     */
    void addOption(const std::string& name, const std::string& description);

    /**
     * @brief      Получение количества вхождений опции
     * 
     * @param[in]  name  Имя опции
     * @return     Количество раз, которое была указана опция
     */
    size_t getOptionCount(const std::string& name) const;

    /**
     * @brief Вывод справки по опциям в лог
     */
    void logHelp() const;

    /**
     * @brief      Отладочный вывод аргументов
     * 
     * @param[in]  argc  Количество аргументов
     * @param[in]  argv  Массив аргументов
     */
    void debugLog(const int argc, const char** argv) const;

public:
    /**
     * @brief      Добавление опции со значением и значением по умолчанию
     * 
     * @tparam     T            Тип значения опции
     * @param[in]  name         Имя опции
     * @param[in]  description  Описание для справки
     * @param[in]  default_value  Значение по умолчанию
     * 
     * @note Если парсер не инициализирован, выводит ошибку в лог
     */
    template <typename T>
    void addOption(const std::string& name, const std::string& description, const T& default_value)
    {
        static_assert(!std::is_same_v<T, void>, "Default value required for non-void options.");

        if (!m_options)
        {
            spdlog::error(" Unable to add option, Option Parser is not initialized");
            return;
        }

        this->m_options->add_options()(name, description, cxxopts::value<T>()->default_value(default_value));

        return;
    }

    /**
     * @brief      Добавление опции со значением (без значения по умолчанию)
     * 
     * @tparam     T            Тип значения опции
     * @param[in]  name         Имя опции
     * @param[in]  description  Описание для справки
     * 
     * @note Если парсер не инициализирован, выводит ошибку в лог
     */
    template <typename T>
    void addOption(const std::string& name, const std::string& description)
    {
        if (!this->m_options)
        {
            spdlog::error(" Unable to add option, Option Parser is not initialized");
            return;
        }

        this->m_options->add_options()(name, description, cxxopts::value<T>());

        return;
    }

    /**
     * @brief      Получение значения опции
     * 
     * @tparam     T       Тип возвращаемого значения (по умолчанию std::string)
     * @param[in]  name    Имя опции
     * @return     Значение опции или значение по умолчанию
     * 
     * @throws     cxxopts::exceptions::exception При ошибках преобразования типа
     * @note       В случае ошибок возвращает T{} и пишет сообщение в лог
     */
    template <typename T = std::string>
    T getOption(const std::string& name) const
    {
        if (!this->m_parsed_options)
        {
            spdlog::error(" Options have not been parsed yet. Call parseOptions() first.");
            return T{};
        }

        if (!hasOption(name))
        {
            spdlog::warn(" Option {} not found. Returning default value.", name);
            return T{};
        }

        try
        {
            return this->m_parsed_options->operator[](name).as<T>();
        }
        catch (const cxxopts::exceptions::exception& e)
        {
            spdlog::error(" Error getting option {}: {}", name, e.what());
        }
        catch (const std::exception& e)
        {
            spdlog::error(" Standard exception while getting option '{}': {}", name, e.what());
        }
        catch (...)
        {
            spdlog::error(" Unknown error occurred while getting option '{}'", name);
        }
        return T{};
    }

private:
    std::unique_ptr<cxxopts::Options>     m_options;         ///< Объект для настройки опций
    std::unique_ptr<cxxopts::ParseResult> m_parsed_options;  ///< Результаты парсинга аргументов
};

} // namespace UTILS

#endif // OPTION_PARSER_HPP