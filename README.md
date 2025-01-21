# ak-mti-d2-implementation

This project is designed for showcasing and testing MTI/MD2 key exchange algorithm using the `libakrypt` library. It provides functionality to exchange keys between multiple subjects, utilizing MTI/MD2 algorithm.

## Features

- **Command-Line Interface:** Uses `cxxopts` for easy command-line argument parsing.
- **Logging:** Employs `spdlog` for informative logging during execution.

## Dependencies

- **libakrypt:** A cryptographic library used for certificate parsing and operations.
- **cxxopts:** A lightweight C++ library for command-line argument parsing.
- **spdlog:** A fast and flexible logging library.

## Generating new certificates

This project does not currently provide embeded tools for generating certificates.
In order to generate new ones, you can use aktool, provided inside libakrypt library.

Here's simple guide for generating all of the nessesary stuff for
1. **Generate self signed certificate and key pair**
```bash
aktool k -nt sign512 --curve ec512b -o test_ca.key --op test_ca.crt \
   --to certificate --days 3650 --ca \
   --id "/cn=Example CA/ct=RU/st=Москва/ot=Blueline Software"
```
2. **Generate subject A and B csr and key pair**
```bash
aktool k -nt sign256 -o subject_a.key --op subject_a.csr --to pem \
   --id "/cn=Subject A/ct=RU/em=subject_a@blueline-software.moscow"
```
```bash
aktool k -nt sign256 -o subject_b.key --op subject_b.csr --to pem \
   --id "/cn=Subject B/ct=RU/em=subject_b@blueline-software.moscow"
```
3. **Sign subject A and B csr**
```bash
aktool k -s subject_a.csr --ca-key test_ca.key --ca-cert test_ca.crt \
   --op subject_a.crt --to pem --days 365
```
```bash
aktool k -s subject_b.csr --ca-key test_ca.key --ca-cert test_ca.crt \
   --op subject_b.crt --to pem --days 365
```
4. **Make sure you didn't fuckup anywhere**
```bash
aktool -v test_ca.crt --verbose
```
```bash
aktool -v subject_a.crt --verbose
```
```bash
aktool -v subject_b.crt --verbose
```

## Usage

Example:
```bash
./build/ak-mti-d2-utility -c ./res/test_ca.crt -a ./res/subject_a.crt -b ./res/subject_b.crt -A ./res/subject_a.key -B ./res/subject_b.key -d
```

Password for importing all keys is 'test'.


## Building

This project uses CMake as its build system. To build the project, follow these steps:

1. **Navigate to the project's root directory:**
```bash
cd path/to/ak-mti-d2-implementation
```

2. **Create a build directory and build**
```bash
cmake . -B ./build/ && cmake --build ./build -j 10
```

This will create a build directory and generate the executable within it.

## License

Well, I don't give a fuck about licensing and stuff, the only thing i despise is propietary bullshit,
so I guess you can call it GNU license.
