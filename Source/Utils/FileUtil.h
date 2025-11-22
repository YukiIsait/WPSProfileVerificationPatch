#pragma once
#include <string>

namespace WPSProfileVerificationPatch {
    class FileUtil {
    private:
        FileUtil() = delete;

    public:
        static bool IsFileExists(const std::string& filePath);
    };
}
