#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <ShlObj.h>

// ============================================================================
// String Conversion Utilities (替代 StringTool.h)
// ============================================================================

inline std::wstring Utf8ToWide(const std::string& utf8str)
{
    if (utf8str.empty()) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), (int)utf8str.size(), NULL, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8str.c_str(), (int)utf8str.size(), &result[0], size_needed);
    return result;
}

inline std::wstring CharToWide(const char* str)
{
    if (!str || str[0] == '\0') return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    std::wstring result(size_needed - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, str, -1, &result[0], size_needed);
    return result;
}

inline std::string WideToUtf8(const std::wstring& wstr)
{
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], size_needed, NULL, NULL);
    return result;
}

template<typename StringType>
inline std::vector<StringType> SplitString(const StringType& str, const typename StringType::value_type* delimiter)
{
    std::vector<StringType> result;
    size_t start = 0;
    size_t end = str.find(delimiter);
    
    while (end != StringType::npos) {
        result.push_back(str.substr(start, end - start));
        start = end + 1;
        end = str.find(delimiter, start);
    }
    result.push_back(str.substr(start));
    return result;
}

// ============================================================================
// File Utilities (替代 FileTool.h)
// ============================================================================

inline std::wstring GetCurrentAppPath()
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return fullPath.substr(0, pos + 1);
    }
    return fullPath;
}

inline bool FileExist(const std::wstring& path)
{
    DWORD attrib = GetFileAttributesW(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES);
}

inline bool CreateDirectoryNested(const std::wstring& path)
{
    // 使用 SHCreateDirectoryEx 创建多级目录
    int ret = SHCreateDirectoryExW(NULL, path.c_str(), NULL);
    return (ret == ERROR_SUCCESS || ret == ERROR_ALREADY_EXISTS || ret == ERROR_FILE_EXISTS);
}

inline std::vector<std::string> ReadAsciiFileLines(const std::wstring& filename)
{
    std::vector<std::string> lines;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        return lines;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // 移除行尾的 \r
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            lines.push_back(line);
        }
    }
    
    return lines;
}

inline bool WriteFile(const std::wstring& filename, const char* data, size_t size)
{
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    file.write(data, size);
    file.close();
    return true;
}

// ============================================================================
// String Formatting (替代 fmt/format.h)
// ============================================================================

template<typename... Args>
inline std::string FormatString(const char* format, Args... args)
{
    int size = snprintf(nullptr, 0, format, args...) + 1;
    if (size <= 0) {
        return "";
    }
    std::string result(size, '\0');
    snprintf(&result[0], size, format, args...);
    result.pop_back(); // 移除 '\0'
    return result;
}

template<typename... Args>
inline std::wstring FormatStringW(const wchar_t* format, Args... args)
{
    int size = _snwprintf(nullptr, 0, format, args...) + 1;
    if (size <= 0) {
        return L"";
    }
    std::wstring result(size, L'\0');
    _snwprintf(&result[0], size, format, args...);
    result.pop_back(); // 移除 '\0'
    return result;
}

// ============================================================================
// Resource Manager (替代 ResManager.h 的 SetResDeleter)
// ============================================================================

// HANDLE 自动管理器
struct HandleDeleter {
    void operator()(HANDLE* h) const {
        if (h && *h && *h != INVALID_HANDLE_VALUE) {
            CloseHandle(*h);
        }
        delete h;
    }
};

using UniqueHandle = std::unique_ptr<HANDLE, HandleDeleter>;

inline UniqueHandle MakeUniqueHandle(HANDLE h)
{
    return UniqueHandle(new HANDLE(h));
}

