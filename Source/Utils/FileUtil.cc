#include <Windows.h>
#include "FileUtil.h"

namespace WPSProfileVerificationPatch {
    bool FileUtil::IsFileExists(const std::string& filePath) {
        DWORD attributes = GetFileAttributesA(filePath.data());
        return (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY));
    }
}
