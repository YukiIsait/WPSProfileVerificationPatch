#include <Windows.h>
#include <stdexcept>
#include <sstream>
#include <format>
#include <memory>
#include <array>
#include "Detours.h"
#include "KRSAVerifyFileHook.h"
#include "FileUtil.h"
#include "ModuleUtil.h"
#include "PatternUtil.h"
#include "VersionUtil.h"

namespace WPSProfileVerificationPatch {
    bool (*KRSAVerifyFileHook::kRSAVerifyFile)(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature) = nullptr;

    bool KRSAVerifyFileHook::KRSAVerifyFile(const std::string& publicKey, const std::string& fileHash, const std::string& fileSignature) {
#if defined WP_DEBUG
        std::stringstream ss;
        ss << "KRSAVerifyFile called with parameters:\r\n";
        ss << "Public Key: " << publicKey << "\r\n";
        ss << "File Hash: " << fileHash << "\r\n";
        ss << "File Signature: " << fileSignature << "\r\n";
        ss << "Verification Result: ";
#endif
        // 如果数字签名全部为 0 则通过校验，否则调用原始校验函数
        for (std::string::size_type i = 0; i < fileSignature.size(); i++) {
            if (fileSignature[i] != '0') {
                bool result = kRSAVerifyFile(publicKey, fileHash, fileSignature);
#if defined WP_DEBUG
                ss << (result ? "Passed" : "Failed");
                MessageBoxA(nullptr, ss.str().data(), "KRSAVerifyFile Debug Information", MB_ICONINFORMATION);
#endif
                return result;
            }
        }
#if defined WP_DEBUG
        ss << "Passed (all-zero signature)";
        MessageBoxA(nullptr, ss.str().data(), "KRSAVerifyFile Debug Information", MB_ICONINFORMATION);
#endif
        return true;
    }

    void KRSAVerifyFileHook::UpdateKRSAVerifyFileAddress() {
#if defined DETOURS_X64
        const std::array<uint16_t, 19> pattern = { 0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x81, 0xEC, 0xD0, 0x02, 0x00, 0x00 };
#elif defined DETOURS_X86
        const std::array<uint16_t, 33> pattern = { 0x55, 0x8B, 0xEC, 0x6A, 0xFF, 0x68, 0x100, 0x100, 0x100, 0x100, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x81, 0xEC, 0x1C, 0x01, 0x00, 0x00, 0xA1, 0x100, 0x100, 0x100, 0x100, 0x33, 0xC5, 0x89, 0x45, 0xEC };
#else
#error "Unsupported architecture"
#endif
        std::string fileName = ModuleUtil::GetFileName(nullptr);
        std::unique_ptr<const uint8_t[]> versionInfoData = VersionUtil::GetVersionInfoData(fileName);
        std::optional<std::span<const uint8_t>> translation = VersionUtil::QueryVersionInfoValue(versionInfoData, "\\VarFileInfo\\Translation");
        if (!translation.has_value()) {
            // 没有找到 Translation，不进行 Hook
            throw std::runtime_error("Failed to find Translation in version info");
        }
        uint16_t langId = *reinterpret_cast<const uint16_t*>(translation->data());
        uint16_t codePage = *reinterpret_cast<const uint16_t*>(translation->data() + 2);
        std::optional<std::span<const uint8_t>> productName = VersionUtil::QueryVersionInfoValue(versionInfoData, std::format("\\StringFileInfo\\{:04x}{:04x}\\ProductName", langId, codePage));
        if (!productName.has_value() || productName->size() != 11 || std::memcmp(productName->data(), "WPS Office", 11) != 0) {
            // ProductName 不是 WPS Office，不进行 Hook
            throw std::runtime_error("ProductName is not WPS Office");
        }
        std::span<const uint8_t> data;
#if defined WP_PACKET
        std::optional<std::span<const uint8_t>> internalName = VersionUtil::QueryVersionInfoValue(versionInfoData, std::format("\\StringFileInfo\\{:04x}{:04x}\\InternalName", langId, codePage));
        if (internalName.has_value() && internalName->size() >= 8 && std::memcmp(internalName->data(), "KPacket", 7) == 0) {
            // InternalName 以 KPacket 开头表明这是安装程序，要在主模块中查找特征码
            HMODULE module = ModuleUtil::GetHandle(std::nullopt);
            data = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(module), ModuleUtil::GetSizeOfMemory(module));
        } else {
            throw std::runtime_error("KRSAVerifyFileHook can only be installed in the installer module");
        }
#elif defined WP_MAIN
        HMODULE module = ModuleUtil::GetSelfHandle();
        std::string krtPath = ModuleUtil::GetBasePath(module) + "krt.dll";
        if (FileUtil::IsFileExists(krtPath)) {
            // 本模块目录下存在 krt.dll 表明这是主程序，要在 krt.dll 中查找特征码
            // 本模块加载时 krt.dll 还未被加载，要主动加载本模块同目录下的 krt.dll
            HMODULE krtModule = LoadLibraryA(krtPath.data());
            if (!krtModule) {
                throw std::runtime_error("Failed to load krt.dll");
            }
            data = std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(krtModule), ModuleUtil::GetSizeOfMemory(krtModule));
        } else {
            throw std::runtime_error("KRSAVerifyFileHook can only be installed in the main module with krt.dll loaded");
        }
#else
#error "Either WP_PACKET or WP_MAIN must be defined"
#endif
#if defined WP_DEBUG
        constexpr size_t maxMatches = 2;
#else
        constexpr size_t maxMatches = 1;
#endif
        std::vector<const uint8_t*> matches = PatternUtil::FindPattern(data, pattern, 0, false, maxMatches);
        if (matches.size() == 0) {
            throw std::runtime_error("Failed to find KRSAVerifyFile pattern");
        }
        if (matches.size() > 1) {
            throw std::runtime_error("Multiple KRSAVerifyFile pattern matches found");
        }
        kRSAVerifyFile = reinterpret_cast<decltype(kRSAVerifyFile)>(matches[0]);
    }

    void KRSAVerifyFileHook::Install() noexcept {
        if (kRSAVerifyFile != nullptr) {
            return;
        }
        try {
            UpdateKRSAVerifyFileAddress(); // 只有这里会抛出异常
        } catch (const std::exception& exception) {
#if defined WP_DEBUG
            MessageBoxA(nullptr, exception.what(), "Hook Failed", MB_ICONSTOP);
#endif
            return;
        }
        if (kRSAVerifyFile == nullptr) {
            return;
        }
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&reinterpret_cast<PVOID&>(kRSAVerifyFile), KRSAVerifyFileHook::KRSAVerifyFile);
        LONG code = DetourTransactionCommit();
        if (code != NO_ERROR) {
            MessageBoxA(nullptr, (std::stringstream() << "Failed to hook KRSAVerifyFile, error code: " << code).str().data(), "Hook Failed", MB_ICONSTOP);
        }
    }

    void KRSAVerifyFileHook::Uninstall() noexcept {
        if (kRSAVerifyFile == nullptr) {
            return;
        }
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&reinterpret_cast<PVOID&>(kRSAVerifyFile), KRSAVerifyFileHook::KRSAVerifyFile);
        LONG code = DetourTransactionCommit();
        if (code != NO_ERROR) {
            MessageBoxA(nullptr, (std::stringstream() << "Failed to unhook KRSAVerifyFile, error code: " << code).str().data(), "Unhook Failed", MB_ICONSTOP);
        }
    }
}
