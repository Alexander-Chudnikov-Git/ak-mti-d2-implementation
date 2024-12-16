#include <iostream>

#include "spdlog/spdlog.h"
#include "spdlog/cfg/env.h"
#include "spdlog/fmt/ostr.h"

int main(const int argc, const char *argv[])
{
	spdlog::info("===========================================================");
    spdlog::info(" Project Information");
    spdlog::info("-----------------------------------------------------------");
    spdlog::info(" Project Name: {:<24} {}", PROJECT_NAME, PROJECT_VERSION);
    spdlog::info(" Compile Time: {}",        COMPILE_TIME);
    spdlog::info(" Compiler:     {:<24} {}", COMPILER_ID, COMPILER_VERSION);
    spdlog::info("===========================================================");

	return 0;
}
