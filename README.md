# Протокол MTI/MD2

Этот проект предназначен для демонстрации и тестирования алгоритма обмена ключами MTI/MD2 с использованием библиотеки libcrypt. Он предоставляет функциональность для обмена ключами между несколькими субъектами, используя алгоритм MTI/MD2.

## Функционал

- **Интерфейс командной строки:** Использует `cxxopts` для простоты анализа аргументов командной строки.
- **Логгирование:** Использует `spdlog` для информативного ведения логов во время выполнения.

## Зависимости

- **libakrypt:** Криптографическая библиотека, используемая для анализа сертификатов и выполнения операций с ними.
- **cxxopts:** Библиотека C++ для анализа аргументов командной строки.
- **spdlog:** Быстрая и гибкая библиотека ведения логов.

## Генерация новых сертификатов

В настоящее время этот проект не предоставляет встроенных инструментов для создания сертификатов.
Для создания новых сертификатов вы можете использовать aktool, предоставляемый в библиотеке libcrypt.

Вот простое руководство по созданию всего необходимого для:
1. **Генерация самозаверяющего сертификата и пары ключей**
```bash
aktool k -nt sign512 --curve ec512b -o test_ca.key --op test_ca.crt \
   --to certificate --days 3650 --ca \
   --id "/cn=Example CA/ct=RU/st=Москва/ot=Blueline Software"
```
2. **Генерация csr субъектов A и B и пары ключей**
```bash
aktool k -nt sign256 -o subject_a.key --op subject_a.csr --to pem \
   --id "/cn=Subject A/ct=RU/em=subject_a@blueline-software.moscow"
```
```bash
aktool k -nt sign256 -o subject_b.key --op subject_b.csr --to pem \
   --id "/cn=Subject B/ct=RU/em=subject_b@blueline-software.moscow"
```
3. **Подпись csr у субъектов A и B**
```bash
aktool k -s subject_a.csr --ca-key test_ca.key --ca-cert test_ca.crt \
   --op subject_a.crt --to pem --days 365
```
```bash
aktool k -s subject_b.csr --ca-key test_ca.key --ca-cert test_ca.crt \
   --op subject_b.crt --to pem --days 365
```
4. **Убедитесь, что сделали все операции верно**
```bash
aktool -v test_ca.crt --verbose
```
```bash
aktool -v subject_a.crt --verbose
```
```bash
aktool -v subject_b.crt --verbose
```

## Использование

Пример:
```bash
./build/ak-mti-d2-utility -c ./res/test_ca.crt -a ./res/subject_a.crt -b ./res/subject_b.crt -A ./res/subject_a.key -B ./res/subject_b.key -d
```

Пароль для импорта всех ключей 'test'.


## Сборка

В этом проекте в качестве системы сборки используется CMake. Чтобы собрать проект, выполните следующие действия:

1. **Перейдите в корневой каталог проекта:**
```bash
cd path/to/ak-mti-d2-implementation
```

2. **Создайте каталог сборки и начните сборку проекта**
```bash
cmake . -B ./build/ && cmake --build ./build -j 10
```

Это создаст каталог 'build' и сгенерирует исполняемый файл внутри него.

## Лицензия

Проект распространяется под лицензией GNUv3. 
