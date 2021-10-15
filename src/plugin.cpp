#include "plugin.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_module.h"
#include "StringTool.h"
#include "FileTool.h"
#include "DebugOutput.h"
#include "Toolhelp.h"
#include "VMQuery.h"
#include <Psapi.h>
#include <memory>
#include "ResManager.h"
#include "fmt/format.h"
#include <cassert>
#include <map>
#include "../build/resource.h"


enum MenuId : int {
    MENU_TEST1 = 0,
    MENU_LOAD_SHELLCODE_INFO,
    MENU_SAVE_SHELLCODE_INFO
};

void SaveShellCodeComment();
void LoadShellCodeComment();
static void cbMenuEntry(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch (info->hEntry)
    {
    case MENU_TEST1:
        break;
    case MENU_LOAD_SHELLCODE_INFO:
        LoadShellCodeComment();
        break;
    case MENU_SAVE_SHELLCODE_INFO:
        SaveShellCodeComment();
        break;
    }
}

static DWORD g_pid = 0;
static HMODULE g_cur_dll_instalce = 0;
static void cbAttachCreateProcessDetach(CBTYPE cbType, void* callbackInfo)
{
    if (cbType == CB_ATTACH) {
        PLUG_CB_ATTACH* info = (PLUG_CB_ATTACH*)callbackInfo;
        g_pid = info->dwProcessId;
    }
    else if (cbType == CB_CREATEPROCESS){
        PLUG_CB_CREATEPROCESS* info = (PLUG_CB_CREATEPROCESS*)callbackInfo;
        g_pid = info->fdProcessInfo->dwProcessId;
    }
    else if(cbType == CB_DETACH){
        //PLUG_CB_DETACH * info = (PLUG_CB_DETACH*)callbackInfo;
        g_pid = 0;
    }
}


//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    _plugin_registercallback(pluginHandle, CB_ATTACH, cbAttachCreateProcessDetach);
    _plugin_registercallback(pluginHandle, CB_CREATEPROCESS, cbAttachCreateProcessDetach);
    _plugin_registercallback(pluginHandle, CB_DETACH, cbAttachCreateProcessDetach);
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
    _plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_TEST1, "&Test1");
    _plugin_menuaddentry(hMenu, MENU_LOAD_SHELLCODE_INFO, "&LoasShellcodeInfo");
    _plugin_menuaddentry(hMenu, MENU_SAVE_SHELLCODE_INFO, "&SaveShellcodeInfo");
}


std::wstring GetMyPluginDataPath()
{
    static std::wstring path = []() -> std::wstring {
        std::wstring s = file_tools::GetCurrentAppPath() + L"ShellcodeComment\\";
        if (!file_tools::FileExist(s)) {
            file_tools::CreateDirectoryNested(s);
        }
        return s;
    }();
    return path;
}



struct MemoryInfo {
    DWORD base_addr = 0;
    size_t size = 0;
};

std::vector<MemoryInfo> GetShellCodeMemoryList()
{
    CToolhelp toolhelp;
    DWORD pid = g_pid;
    if (pid == 0) {
        dputs("GetShellCodeMemoryList Pid is 0");
        return {};
    }
    toolhelp.CreateSnapshot(TH32CS_SNAPALL, pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION,FALSE, pid);
    if (!hProcess) {
        DWORD last_error = ::GetLastError();
        dprintf("GetShellCodeMemoryList OpenProcess Failed:%d\n", last_error);
        return {};
    }
    SetResDeleter(hProcess, [](HANDLE& h) {::CloseHandle(h); });
    auto HasMappedModule = [&toolhelp, &hProcess](VMQUERY* pvmq) {
        if (pvmq->dwRgnStorage == MEM_PRIVATE && (pvmq->dwRgnProtection & PAGE_EXECUTE_READWRITE) > 0) {
            MODULEENTRY32 me = { 0 };
            me.dwSize = sizeof(MODULEENTRY32);
            if (toolhelp.ModuleFind(pvmq->pvRgnBaseAddress, &me) && _tcslen(me.szExePath) > 0) {
                return true;
            }
            else {
                wchar_t module_name[MAX_PATH];
                if (GetMappedFileNameW(hProcess, pvmq->pvRgnBaseAddress, module_name, MAX_PATH) > 0) {
                    return true;
                }
            }
        }
        return false;
    };

    BOOL bOk = TRUE;
    DWORD pvAddress = NULL;
    std::vector<MemoryInfo> result;
    while (bOk) {
        VMQUERY vmq;
        bOk = VMQuery(hProcess, (LPCVOID)pvAddress, &vmq);
        if (bOk) {
            if (vmq.dwRgnStorage == MEM_PRIVATE && (vmq.dwRgnProtection & PAGE_EXECUTE_READWRITE) > 0 && !HasMappedModule(&vmq)) {
                MemoryInfo mem_info;
                mem_info.base_addr = (DWORD)vmq.pvRgnBaseAddress;
                mem_info.size = vmq.RgnSize;
                result.push_back(mem_info);
            }
            pvAddress = (DWORD)vmq.pvRgnBaseAddress + vmq.RgnSize;
        }
    }
    return result;
}
std::vector<unsigned char> ReadMem(LPVOID addr, size_t size)
{
    if (g_pid == 0) {
        dputs("ReadMem g_pid is 0");
        return {};
    }
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_pid);
    if (!hProcess) {
        DWORD last_error = ::GetLastError();
        dprintf("GetShellCodeMemoryList OpenProcess Failed:%d\n", last_error);
        return {};
    }
    SetResDeleter(hProcess, [](HANDLE& h) {::CloseHandle(h); });
    std::unique_ptr<unsigned char[]> feature_buffer(new unsigned char[size]);
    SIZE_T read_size = 0;
    if (::ReadProcessMemory(hProcess, addr, (LPVOID)feature_buffer.get(), size, &read_size) && read_size == size) {
        std::vector<unsigned char> readed(size);
        memcpy(readed.data(), feature_buffer.get(), size);
        return readed;
    }
    return {};
}
struct ShellCodeFeature {
    DWORD feature_offset = 0;
    std::vector<unsigned char> feature_code;
};

struct ShellCodeLineData {
    DWORD offset = 0;
    std::wstring text;
};

enum ManualInfoType : int{
    NM_COMMENT = 0,
    NM_LABEL,
};

std::vector<ShellCodeLineData> EnumShellCodeNames(const MemoryInfo& vmq, int info_type)
{
    std::vector<ShellCodeLineData>  comments;
    if (info_type == NM_COMMENT) {
        ListInfo list_info;
        Script::Comment::GetList(&list_info);
        std::vector<Script::Comment::CommentInfo> comment_list;
        BridgeList<Script::Comment::CommentInfo>::ToVector(&list_info, comment_list, true);
        for (auto& comment : comment_list) {
            //comments.push_back(
            if (comment.manual &&  chINRANGE(vmq.base_addr, comment.rva, vmq.base_addr + vmq.size)) {
                ShellCodeLineData info;
                info.offset = comment.rva - vmq.base_addr;
                info.text = string_tool::utf8_to_wstring(comment.text);
                comments.push_back(info);
            }
        }
    }
    else if(info_type == NM_LABEL){
        ListInfo list_info;
        Script::Label::GetList(&list_info);
        std::vector<Script::Label::LabelInfo> comment_list;
        BridgeList<Script::Label::LabelInfo>::ToVector(&list_info, comment_list, true);
        for (auto& comment : comment_list) {
            //comments.push_back(
            if (comment.manual && chINRANGE(vmq.base_addr, comment.rva, vmq.base_addr + vmq.size)) {
                ShellCodeLineData info;
                info.offset = comment.rva - vmq.base_addr;
                info.text = string_tool::utf8_to_wstring(comment.text);
                comments.push_back(info);
            }
        }
    }
    return comments;
}


struct UserCustomShellCode {
    DWORD size = 0;
    std::wstring name;
    ShellCodeFeature feature;
};
std::vector<UserCustomShellCode> g_user_custom_shellcode_features;



std::string BufferToLine(const std::vector<unsigned char>& buffer)
{
    std::string s;
    for (auto& ch : buffer) {
        s += fmt::format("{:02X}", ch);
    }
    return s;
}
std::vector<unsigned char> HexLineToBuffer(const std::string& line)
{
    //450306
    assert(line.length() % 2 == 0);
    std::vector<unsigned char> result;
    for (size_t i = 0; i < line.length() / 2; i++) {
        std::string hex_str = line.substr(i * 2, 2);
        result.push_back((unsigned char)std::stoul(hex_str, nullptr, 16));
    }
    return result;
}
void LoadUserCustomShellCodeFeature()
{
    g_user_custom_shellcode_features.clear();

    char process_name[MAX_PATH] = { 0 };
    if (!Script::Module::GetMainModuleName(process_name)) {
        dputs("LoadUserCustomShellCodeFeature GetMainModuleName Failed");
        return;
    }
    std::wstring file_name = GetMyPluginDataPath() + string_tool::CharToWide(process_name) + L".shellcode_features";
    auto lines = file_tools::ReadAsciiFileLines(file_name);
    for (auto& line : lines) {
        auto items = string_tool::SplitStrByFlag<std::string>(line, "|");
        if (items.size() == 4) {
            size_t shellcode_size = std::stoul(items.at(0), nullptr, 16);
            std::string name = items.at(1);
            size_t feature_offset = std::stoul(items.at(2), nullptr, 16);
            std::vector<unsigned char> feature_code = HexLineToBuffer(items.at(3));

            UserCustomShellCode custum_shellcode_feature;
            custum_shellcode_feature.size = shellcode_size;
            custum_shellcode_feature.name = string_tool::utf8_to_wstring(name);
            custum_shellcode_feature.feature.feature_code = feature_code;
            custum_shellcode_feature.feature.feature_offset = feature_offset;
            g_user_custom_shellcode_features.push_back(custum_shellcode_feature);
        }
    }
}

std::map<DWORD, std::wstring> g_analyzed_custom_shellcode_list;
void AnalyzeCacheShellCodeBase()
{
    auto shell_code_list = GetShellCodeMemoryList();
    for (const auto& shell_code : shell_code_list) {
        for (auto& feature : g_user_custom_shellcode_features) {
            if (shell_code.size == feature.size) {
                auto bytes = ReadMem((unsigned char*)shell_code.base_addr + feature.feature.feature_offset, feature.feature.feature_code.size());
                if (memcmp(bytes.data(), feature.feature.feature_code.data(), feature.feature.feature_code.size()) == 0) {
                    g_analyzed_custom_shellcode_list[shell_code.base_addr] = feature.name;
                }
            }
        }
    }
}


void SaveUserCustomShellCodeFeature()
{
    char process_name[MAX_PATH] = { 0 };
    if (!Script::Module::GetMainModuleName(process_name)) {
        dputs("LoadUserCustomShellCodeFeature GetMainModuleName Failed");
        return;
    }
    std::wstring file_name = GetMyPluginDataPath() + string_tool::CharToWide(process_name) + L".shellcode_features";

    std::string file_content;
    for (auto& feature : g_user_custom_shellcode_features) {
        std::string line = fmt::format("{:08X}|{}|{:08X}|{}\r\n", feature.size, string_tool::wstring_to_utf8(feature.name), feature.feature.feature_offset, BufferToLine(feature.feature.feature_code));
        file_content += line;
    }
    file_tools::WriteFile(file_name, file_content.c_str(), file_content.length());
}



std::wstring GetUserCustomShellCodeName(DWORD addr) {
    auto iter = g_analyzed_custom_shellcode_list.find(addr);
    if (iter == g_analyzed_custom_shellcode_list.end()) {
        return L"";
    }
    else {
        return iter->second;
    }
}
struct DialogCustomData {
    DWORD base_addr = 0;
    wchar_t name[100];
    DWORD feature_addr_start;
    DWORD feature_code_size;
};


BOOL CALLBACK InputShellCodeFeatureDialogProc(HWND dlg,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        std::string text = fmt::format("{:#04x}", ((uint64_t)((DialogCustomData*)lParam)->base_addr));
        SetDlgItemTextA(dlg, IDC_EDIT_BASE_ADDR, text.c_str());
        ::SetWindowLongPtr(dlg, GWLP_USERDATA, lParam);
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
        {
            wchar_t feature_name[100] = { 0 };
            wchar_t szstart_addr[100] = { 0 };
            wchar_t szend_addr[100] = { 0 };
            GetDlgItemTextW(dlg, IDC_EDIT_NAME, feature_name, 100);
            GetDlgItemTextW(dlg, IDC_EDIT_FEATURE_START_ADDR, szstart_addr, 100);
            GetDlgItemTextW(dlg, IDC_EDIT_FEATURE_END_ADDR, szend_addr, 100);
            DWORD start_addr = std::stoul(szstart_addr, nullptr, 16);
            DWORD end_addr = std::stoul(szend_addr, nullptr, 16);
            DWORD feature_code_size = end_addr - start_addr;
            if (wcslen(feature_name) > 0 && start_addr >= 0 && feature_code_size > 0) {
                DialogCustomData* data = (DialogCustomData*)::GetWindowLongPtr(dlg, GWLP_USERDATA);
                wcscpy_s(data->name, feature_name);
                data->feature_addr_start = start_addr;
                data->feature_code_size = feature_code_size;
                ::EndDialog(dlg, IDOK);
            }
            else {
                ::MessageBoxW(dlg, L"Input Error", NULL, MB_OK);
            }
            break;
        }
        case IDCANCEL:
            ::EndDialog(dlg, IDCANCEL);
            break;
        }
        break;
    default:
        break;
    }
    return 0;
}


bool DialogInputAddShellCodeFeature(DWORD shellcode_base_addr, DWORD shellcode_size, std::wstring& name)
{
    //填充用户在意的shellcode

    HWND main_window = (HWND)hwndDlg;

    DialogCustomData dlg_data;
    dlg_data.base_addr = shellcode_base_addr;
    INT_PTR dlg_ret = DialogBoxParam(g_cur_dll_instalce, MAKEINTRESOURCE(IDD_DIALOG_INPUT_SHELLCODE_FEATURE), main_window, InputShellCodeFeatureDialogProc, (LPARAM)&dlg_data);
    if (dlg_ret == IDOK) {
        if (std::find_if(g_user_custom_shellcode_features.begin(), g_user_custom_shellcode_features.end(), [&dlg_data](const UserCustomShellCode& s) {return s.name == dlg_data.name; }) != g_user_custom_shellcode_features.end()) {
            ::MessageBoxA(main_window, "ShellCode名称重复", NULL, MB_OK);
            return false;
        }
        else {
            if (g_pid == 0) {
                dputs("ReadMem g_pid is 0");
                return {};
            }
            HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, g_pid);
            if (!hProcess) {
                DWORD last_error = ::GetLastError();
                dprintf("GetShellCodeMemoryList OpenProcess Failed:%d\n", last_error);
                return {};
            }
            SetResDeleter(hProcess, [](HANDLE& h) {::CloseHandle(h); });

            std::unique_ptr<unsigned char[]> feature_buffer(new unsigned char[dlg_data.feature_code_size]);
            SIZE_T read_size = 0;
            if (::ReadProcessMemory(hProcess, (LPCVOID)(dlg_data.feature_addr_start), (LPVOID)feature_buffer.get(), dlg_data.feature_code_size, &read_size) && read_size == dlg_data.feature_code_size) {
                UserCustomShellCode custom_shellcode;
                custom_shellcode.size = shellcode_size;
                custom_shellcode.name = dlg_data.name;
                for (size_t i = 0; i < dlg_data.feature_code_size; i++) {
                    custom_shellcode.feature.feature_code.push_back(feature_buffer[i]);
                }
                custom_shellcode.feature.feature_offset = dlg_data.feature_addr_start - dlg_data.base_addr;
                name = custom_shellcode.name;
                g_user_custom_shellcode_features.push_back(custom_shellcode);
                SaveUserCustomShellCodeFeature();
                return true;
            }
            else {
                dputs("ReadProcessMemory Failed");
                return false;
            }
        }
    }
    else {
        return false;
    }
}

std::wstring GetCommentSavePath(const std::wstring& exe_name)
{
    return GetMyPluginDataPath() + exe_name + L"\\";
}


void LoadShellCodeComment()
{
    LoadUserCustomShellCodeFeature();
    AnalyzeCacheShellCodeBase();
    //这里要检测是否要未保存的，要不然Load会覆盖
    {
        auto shell_code_list = GetShellCodeMemoryList();
        HWND main_window = (HWND)hwndDlg;
        for (const auto& vmq : shell_code_list) {
            std::vector<ShellCodeLineData> comments = EnumShellCodeNames(vmq, NM_COMMENT);
            std::vector<ShellCodeLineData> labels = EnumShellCodeNames(vmq, NM_LABEL);
            if (comments.size() > 0 || labels.size() > 0) {
                auto line = comments.size() > 0 ? comments.at(0) : labels.at(0);
                if (IDYES == MessageBoxW(main_window, fmt::format(L"{:08X} {:08X}  {:08X}", vmq.base_addr, line.offset, vmq.base_addr + line.offset).c_str(), L"之前保存的注释可能会丢失，是否继续？", MB_YESNO)) {
                    break;
                }
                else {
                    return;
                }
            }

        }
    }
    char process_name[MAX_PATH] = { 0 };
    if (!Script::Module::GetMainModuleName(process_name)) {
        dputs("LoadUserCustomShellCodeFeature GetMainModuleName Failed");
        return;
    }
    std::wstring path = GetCommentSavePath(string_tool::CharToWide(process_name));
    if (!file_tools::FileExist(path)) {
        file_tools::CreateDirectoryNested(path);
    }

    dputs("LoadShellcode Feature");

    auto shell_code_list = GetShellCodeMemoryList();
    for (const auto& vmq : shell_code_list) {
        std::wstring name = GetUserCustomShellCodeName(vmq.base_addr);
        if (name.length() > 0) {
            dprintf("ShellCode:0x%08x  size:0x%08x\n", vmq.base_addr, vmq.size);
            std::wstring file_name = path + name + L".txt";
            auto lines = file_tools::ReadAsciiFileLines(file_name);
            for (const auto& line : lines) {
                //0003B853^COMMENT^ssssssssss;
                auto flag = line.find('^');
                if (flag == std::string::npos) {
                    dputs("^ is not find1");
                    continue;
                }
                DWORD offset = std::stoul(line.substr(0, flag), nullptr, 16);

                auto flag2 = line.find('^', flag + 1);
                if (flag2 == std::string::npos) {
                    dputs("^ is not find2");
                    continue;
                }
                std::string type_name = line.substr(flag + 1, flag2 - (flag + 1));
                if (type_name.empty() || (type_name != "COMMENT" && type_name != "LABEL")) {
                    dputs("^ is not find not comment and label");
                    continue;
                }

                std::string text = line.substr(flag2 + 1);

                dprintf("%s  addr:0x%08x,:%s\n", type_name.c_str(), vmq.base_addr + offset, text.c_str());

                char ansi_text[500] = { 0 };
                strcpy_s(ansi_text, text.c_str());
                if (type_name == "COMMENT") {
                    Script::Comment::Set(vmq.base_addr + offset,  ansi_text, true);
                }
                else if (type_name == "LABEL") {
                    Script::Label::Set(vmq.base_addr + offset,ansi_text, true);
                }
            }
        }
    }
}




void SaveShellCodeComment()
{
    //遍历 ShellCode
    //遍历 ShellCode里注释
    //保存注释 怎么标识一个ShellCode? 1.大小 2.特征码（shellcode md5?） 感觉也不行。因为shellcode有些地址每次加载都会被换掉 所以只能自己标识，那就用指定偏移的一段特征码标识吧
    LoadUserCustomShellCodeFeature();
    AnalyzeCacheShellCodeBase();

    char process_name[MAX_PATH] = { 0 };
    if (!Script::Module::GetMainModuleName(process_name)) {
        dputs("LoadUserCustomShellCodeFeature GetMainModuleName Failed");
        return;
    }

    std::wstring path = GetCommentSavePath(string_tool::CharToWide(process_name));
    if (!file_tools::FileExist(path)) {
        file_tools::CreateDirectoryNested(path);
    }

    auto shell_code_list = GetShellCodeMemoryList();
    for (const auto& vmq : shell_code_list) {
        std::vector<ShellCodeLineData> comments = EnumShellCodeNames(vmq, NM_COMMENT);
        std::vector<ShellCodeLineData> labels = EnumShellCodeNames(vmq, NM_LABEL);


        if (comments.size() > 0 || labels.size()) {
            std::wstring name = GetUserCustomShellCodeName(vmq.base_addr);
            if (name.length() == 0) {
                if (!DialogInputAddShellCodeFeature(vmq.base_addr, vmq.size, name)) {
                    continue;
                }
                else {
                    g_analyzed_custom_shellcode_list[vmq.base_addr] = name;
                }
            }
            std::wstring file_name = path + name + L".txt";
            std::string file_content;
            for (const auto& comment : comments) {
                std::string line = fmt::format("{:08X}^COMMENT^{}\r\n", comment.offset, string_tool::wstring_to_utf8(comment.text));
                file_content += line;
            }
            for (const auto& comment : labels) {
                std::string line = fmt::format("{:08X}^LABEL^{}\r\n", comment.offset, string_tool::wstring_to_utf8(comment.text));
                file_content += line;
            }
            file_tools::WriteFile(file_name, file_content.c_str(), file_content.length());
        }
    }
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_cur_dll_instalce = hModule;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}