#include "plugin.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_gui.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "PluginHelper.h"

#include "CmnHdr.h"
#include <memory>
#include <cassert>
#include <map>
#include <set>
#include <CommCtrl.h>
#include "../build/resource.h"

extern bool ModUnload(duint Base);


enum MenuId : int {
    MENU_LOAD_SHELLCODE_INFO = 0,
    MENU_ENUM_SHELLCODE,
    MENU_UNLOAD_VIRTUAL_MODULES,
    MENU_VIEW_FEATURES,
    MENU_MARK_AS_SHELLCODE,
};


void LoadShellCodeComment();
void EnumShellCodeByFeature();
void UnloadAllVirtualModules();
void ViewShellCodeFeatures();
void MarkAsShellCode();

bool cbRemoveAllVirtualModCommand(int argc, char** argv);
static void cbMenuEntry(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch (info->hEntry)
    {
    case MENU_LOAD_SHELLCODE_INFO:
        LoadShellCodeComment();
        break;
    case MENU_ENUM_SHELLCODE:
        EnumShellCodeByFeature();
        break;
    case MENU_UNLOAD_VIRTUAL_MODULES:
        UnloadAllVirtualModules();
        break;
    case MENU_VIEW_FEATURES:
        ViewShellCodeFeatures();
        break;
    case MENU_MARK_AS_SHELLCODE:
        MarkAsShellCode();
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
    
    _plugin_registercommand(pluginHandle, "removeallvirtualmod", cbRemoveAllVirtualModCommand, true);
    
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
    _plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
    _plugin_unregistercommand(pluginHandle, "removeallvirtualmod");
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_LOAD_SHELLCODE_INFO, "&Load ShellCode as Virtual Module");
    _plugin_menuaddentry(hMenu, MENU_ENUM_SHELLCODE, "&Enum ShellCode");
    _plugin_menuaddentry(hMenu, MENU_UNLOAD_VIRTUAL_MODULES, "&Unload All Virtual Modules");
    _plugin_menuaddentry(hMenu, MENU_VIEW_FEATURES, "&View ShellCode Features");
    _plugin_menuaddentry(hMenuDisasm, MENU_MARK_AS_SHELLCODE, "&Mark as ShellCode");
}


std::wstring GetMyPluginDataPath()
{
    static std::wstring path = []() -> std::wstring {
        std::wstring s = GetCurrentAppPath() + L"ShellcodeComment\\";
        if (!FileExist(s)) {
            CreateDirectoryNested(s);
        }
        return s;
    }();
    return path;
}



struct MemoryInfo {
    DWORD base_addr = 0;
    size_t size = 0;
};

std::vector<MemoryInfo> GetShellCodeMemoryList(const std::vector<DWORD>& target_sizes)
{
    std::vector<MemoryInfo> result;
    
    // 如果目标大小列表为空，直接返回空结果
    if (target_sizes.empty()) {
        return result;
    }
    
    // 使用 x64dbg 的 DbgMemMap API 获取所有内存页信息
    MEMMAP memmap = { 0 };
    if (!DbgMemMap(&memmap)) {
        dputs("GetShellCodeMemoryList DbgMemMap Failed");
        return {};
    }
    
    dprintf("Scanning memory for %d specific size(s)...\n", target_sizes.size());
    
    // 遍历所有内存页，筛选出符合 shellcode 特征的内存
    for (int i = 0; i < memmap.count; i++) {
        MEMPAGE* page = &memmap.page[i];
        MEMORY_BASIC_INFORMATION* mbi = &page->mbi;
        
        // 筛选条件：
        // 1. MEM_PRIVATE: 私有内存（不是镜像文件或映射文件）
        // 2. PAGE_EXECUTE_READWRITE: 可执行、可读、可写
        // 3. MEM_COMMIT: 已提交状态
        // 4. info[0] == 0: 没有关联的模块信息
        // 5. size 在目标大小列表中
        if (mbi->Type == MEM_PRIVATE && 
            (mbi->Protect & PAGE_EXECUTE_READWRITE) &&
            mbi->State == MEM_COMMIT &&
            page->info[0] == '\0') {
            
            // 检查当前内存块大小是否在目标列表中
            bool size_matched = false;
            for (DWORD target_size : target_sizes) {
                if (mbi->RegionSize == target_size) {
                    size_matched = true;
                    break;
                }
            }
            
            if (size_matched) {
                MemoryInfo mem_info;
                mem_info.base_addr = (DWORD)mbi->BaseAddress;
                mem_info.size = mbi->RegionSize;
                result.push_back(mem_info);
                
                dprintf("  Found: Base=0x%08X, Size=0x%08X\n", 
                        mem_info.base_addr, mem_info.size);
            }
        }
    }
    
    dprintf("Found %d matching memory region(s)\n", result.size());
    return result;
}
std::vector<unsigned char> ReadMem(LPVOID addr, size_t size)
{
    std::vector<unsigned char> result(size);
    duint size_read = 0;
    
    // 使用 x64dbg 的 Script::Memory::Read API
    if (Script::Memory::Read((duint)addr, result.data(), size, &size_read) && size_read == size) {
        return result;
    }
    
    // 读取失败，返回空
    return {};
}
struct ShellCodeFeature {
    DWORD feature_offset = 0;
    std::vector<unsigned char> feature_code;
};

struct UserCustomShellCode {
    DWORD size = 0;
    std::wstring name;
    ShellCodeFeature feature;
};




std::string BufferToLine(const std::vector<unsigned char>& buffer)
{
    std::string s;
    for (auto& ch : buffer) {
        char hex[3];
        sprintf_s(hex, "%02X", ch);
        s += hex;
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
std::vector<UserCustomShellCode>  LoadUserCustomShellCodeFeature()
{
    std::vector<UserCustomShellCode> result;

    char process_name[MAX_PATH] = { 0 };
    if (!Script::Module::GetMainModuleName(process_name)) {
        dputs("LoadUserCustomShellCodeFeature GetMainModuleName Failed");
        return {};
    }
    std::wstring file_name = GetMyPluginDataPath() + CharToWide(process_name) + L".shellcode_features";
    auto lines = ReadAsciiFileLines(file_name);
    for (auto& line : lines) {
        auto items = SplitString<std::string>(line, "|");
        if (items.size() == 4) {
            size_t shellcode_size = std::stoul(items.at(0), nullptr, 16);
            std::string name = items.at(1);
            size_t feature_offset = std::stoul(items.at(2), nullptr, 16);
            std::vector<unsigned char> feature_code = HexLineToBuffer(items.at(3));

            UserCustomShellCode custum_shellcode_feature;
            custum_shellcode_feature.size = shellcode_size;
            custum_shellcode_feature.name = Utf8ToWide(name);
            custum_shellcode_feature.feature.feature_code = feature_code;
            custum_shellcode_feature.feature.feature_offset = feature_offset;
            result.push_back(custum_shellcode_feature);
        }
    }
    return result;
}


std::map<DWORD, std::wstring>  AnalyzeCacheShellCodeBase(const std::vector<UserCustomShellCode>& shellcode_features)
{
    std::map<DWORD, std::wstring> result;
    
    // 提取所有 shellcode 的唯一大小，用于过滤内存扫描
    std::vector<DWORD> target_sizes;
    for (const auto& feature : shellcode_features) {
        // 检查是否已经存在，避免重复
        bool exists = false;
        for (DWORD size : target_sizes) {
            if (size == feature.size) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            target_sizes.push_back(feature.size);
        }
    }
    
    // 只扫描特定大小的内存块，提高效率
    auto shell_code_list = GetShellCodeMemoryList(target_sizes);
    
    for (const auto& shell_code : shell_code_list) {
        for (auto& feature : shellcode_features) {
            if (shell_code.size == feature.size) {
                auto bytes = ReadMem((unsigned char*)shell_code.base_addr + feature.feature.feature_offset, feature.feature.feature_code.size());
                if (memcmp(bytes.data(), feature.feature.feature_code.data(), feature.feature.feature_code.size()) == 0) {
                    result[shell_code.base_addr] = feature.name;
                }
            }
        }
    }
    return result;
}


void SaveUserCustomShellCodeFeature(const std::vector<UserCustomShellCode>& shellcode_features)
{
    char process_name[MAX_PATH] = { 0 };
    if (!Script::Module::GetMainModuleName(process_name)) {
        dputs("LoadUserCustomShellCodeFeature GetMainModuleName Failed");
        return;
    }
    std::wstring file_name = GetMyPluginDataPath() + CharToWide(process_name) + L".shellcode_features";

    std::string file_content;
    for (auto& feature : shellcode_features) {
        std::string line = FormatString("%08X|%s|%08X|%s\r\n", 
            feature.size, 
            WideToUtf8(feature.name).c_str(), 
            feature.feature.feature_offset, 
            BufferToLine(feature.feature.feature_code).c_str());
        file_content += line;
    }
    WriteFile(file_name, file_content.c_str(), file_content.length());
}


void LoadShellCodeComment()
{
    // 加载 shellcode 特征码配置
    auto shellcode_features = LoadUserCustomShellCodeFeature();
    if (shellcode_features.empty()) {
        dputs("No shellcode features found");
                    return;
    }

    // 通过特征码分析并定位 shellcode 内存地址（内部已经使用 size 过滤优化）
    auto shellcode_map = AnalyzeCacheShellCodeBase(shellcode_features);
    if (shellcode_map.empty()) {
        dputs("No matching shellcode found in memory");
        return;
    }

    dputs("Loading shellcode as virtual modules...");

    // 创建名称到大小的映射，用于显示信息
    std::map<std::wstring, DWORD> name_to_size_map;
    for (const auto& feature : shellcode_features) {
        name_to_size_map[feature.name] = feature.size;
    }

    // 获取当前所有模块列表，存储虚拟模块的名称和base地址
    ListInfo module_list;
    std::map<std::string, duint> existing_virtual_modules;  // 名称 -> base地址
    
    if (Script::Module::GetList(&module_list)) {
        std::vector<Script::Module::ModuleInfo> modules;
        BridgeList<Script::Module::ModuleInfo>::ToVector(&module_list, modules, true);
        
        for (const auto& mod : modules) {
            if (strncmp(mod.path, "virtual:\\", 9) == 0) {
                existing_virtual_modules[mod.path + 9] = mod.base;
            }
        }
    }

    int success_count = 0;
    int failed_count = 0;
    int skipped_count = 0;
    int relocated_count = 0;

    // 直接遍历匹配结果，不需要再次扫描内存
    for (const auto& entry : shellcode_map) {
        DWORD base_addr = entry.first;
        std::wstring name = entry.second;

            if (name.length() > 0) {
            // 构造 x64dbg 命令：virtualmod <name>,<address>
            std::string module_name = WideToUtf8(name);
            DWORD size = name_to_size_map[name];
            
            // 检查是否已经存在同名的虚拟模块
            auto it = existing_virtual_modules.find(module_name);
            if (it != existing_virtual_modules.end()) {
                duint existing_base = it->second;
                
                if (existing_base == base_addr) {
                    // Base地址相同，跳过
                    dprintf("Skipped (already loaded): %s at 0x%08X (size: 0x%08X)\n", 
                            module_name.c_str(), base_addr, size);
                    skipped_count++;
                    continue;
                }
                else {
                    // Base地址不同，重要警告
                    dprintf("===========================================\n");
                    dprintf("!!! WARNING: ShellCode relocated !!!\n");
                    dprintf("  Module name: %s\n", module_name.c_str());
                    dprintf("  Old base: 0x%08X\n", existing_base);
                    dprintf("  New base: 0x%08X\n", base_addr);
                    dprintf("  Size: 0x%08X\n", size);
                    dprintf("===========================================\n");
                    
                    char msg[512];
                    sprintf_s(msg, "ShellCode '%s' has been relocated!\n\nOld base: 0x%08X\nNew base: 0x%08X\n\nPlease unload the old virtual module first.", 
                              module_name.c_str(), existing_base, base_addr);
                    MessageBoxA(hwndDlg, msg, "ShellCode Relocated Warning", MB_ICONWARNING);
                    
                    relocated_count++;
                    continue;
                }
            }
            
            char cmd[512];
            sprintf_s(cmd, "virtualmod %s,%X", module_name.c_str(), base_addr);

            // 执行命令
            if (DbgCmdExecDirect(cmd)) {
                dprintf("? Created virtual module: %s at 0x%08X (size: 0x%08X)\n", 
                        module_name.c_str(), base_addr, size);
                success_count++;
            }
            else {
                dprintf("? Failed to create virtual module: %s at 0x%08X\n", 
                        module_name.c_str(), base_addr);
                failed_count++;
            }
        }
    }

    // 显示统计信息
    dprintf("===========================================\n");
    dprintf("Virtual module creation completed:\n");
    dprintf("  Total shellcode features: %d\n", shellcode_features.size());
    dprintf("  Matched in memory: %d\n", shellcode_map.size());
    dprintf("  Successfully created: %d\n", success_count);
    dprintf("  Skipped (already loaded): %d\n", skipped_count);
    dprintf("  Relocated (base changed): %d\n", relocated_count);
    dprintf("  Failed: %d\n", failed_count);
    dprintf("===========================================\n");

    // 如果有成功创建的，刷新模块列表
    if (success_count > 0) {
        DbgCmdExecDirect("modlist");
    }
}




void EnumShellCodeByFeature()
{
    auto shellcode_features = LoadUserCustomShellCodeFeature();
    auto shellcode_map = AnalyzeCacheShellCodeBase(shellcode_features);

    dputs("===========================================");
    dprintf("Found %d shellcode features in config\n", shellcode_features.size());
    dprintf("Matched %d shellcode(s) in memory:\n", shellcode_map.size());
    dputs("===========================================");
    
    for (auto it : shellcode_map) {
        dprintf("  [%s] at 0x%08X\n", WideToUtf8(it.second).c_str(), it.first);
    }
    
    if (shellcode_map.empty()) {
        dputs("No shellcode found. Please ensure:");
        dputs("  1. The target process contains the shellcode");
        dputs("  2. Feature signatures are correctly configured");
    }
}

void UnloadAllVirtualModules()
{
    ListInfo module_list;
    if (!Script::Module::GetList(&module_list)) {
        dputs("Failed to get module list");
        return;
    }

    std::vector<Script::Module::ModuleInfo> modules;
    BridgeList<Script::Module::ModuleInfo>::ToVector(&module_list, modules, true);

    int unload_count = 0;
    int failed_count = 0;

    dputs("Scanning for virtual modules...");

    for (const auto& mod : modules) {
        if (strncmp(mod.path, "virtual:\\", 9) == 0) {
            const char* module_name = mod.path + 9;
            
            char cmd[512];
            sprintf_s(cmd, "virtualmoddel %s", module_name);
            
            if (DbgCmdExecDirect(cmd)) {
                dprintf("? Unloaded virtual module: %s\n", module_name);
                unload_count++;
            }
            else {
                dprintf("? Failed to unload virtual module: %s\n", module_name);
                failed_count++;
            }
        }
    }

    dputs("===========================================");
    dprintf("Unload completed:\n");
    dprintf("  Successfully unloaded: %d\n", unload_count);
    dprintf("  Failed: %d\n", failed_count);
    dputs("===========================================");

    if (unload_count > 0) {
        GuiUpdateAllViews();
    }
}

void MarkAsShellCode()
{
    duint sel_start = 0, sel_end = 0;
    
    if (!Script::Gui::Disassembly::SelectionGet(&sel_start, &sel_end)) {
        MessageBoxA(hwndDlg, "Please select shellcode range in disassembly window", "Error", MB_ICONERROR);
        return;
    }
    
    if (sel_start >= sel_end) {
        MessageBoxA(hwndDlg, "Invalid selection range", "Error", MB_ICONERROR);
        return;
    }
    
    duint shellcode_base = Script::Memory::GetBase(sel_start);
    if (shellcode_base == 0) {
        MessageBoxA(hwndDlg, "Failed to get memory base address", "Error", MB_ICONERROR);
        return;
    }
    
    duint shellcode_size = Script::Memory::GetSize(sel_start);
    if (shellcode_size == 0) {
        MessageBoxA(hwndDlg, "Failed to get memory size", "Error", MB_ICONERROR);
        return;
    }
    
    char shellcode_name[256] = {0};
    
    if (!GuiGetLineWindow("Enter ShellCode Name", shellcode_name)) {
        return;
    }
    
    if (strlen(shellcode_name) == 0) {
        MessageBoxA(hwndDlg, "ShellCode name cannot be empty", "Error", MB_ICONERROR);
        return;
    }
    
    auto existing_features = LoadUserCustomShellCodeFeature();
    std::wstring wname = CharToWide(shellcode_name);
    
    for (const auto& feature : existing_features) {
        if (feature.name == wname) {
            MessageBoxA(hwndDlg, "ShellCode name already exists", "Error", MB_ICONERROR);
            return;
        }
    }
    
    DWORD feature_offset = sel_start - shellcode_base;
    DWORD feature_size = sel_end - sel_start;
    
    auto feature_bytes = ReadMem((LPVOID)sel_start, feature_size);
    if (feature_bytes.empty()) {
        MessageBoxA(hwndDlg, "Failed to read feature bytes", "Error", MB_ICONERROR);
        return;
    }
    
    UserCustomShellCode new_feature;
    new_feature.size = shellcode_size;
    new_feature.name = wname;
    new_feature.feature.feature_offset = feature_offset;
    new_feature.feature.feature_code = feature_bytes;
    
    existing_features.push_back(new_feature);
    SaveUserCustomShellCodeFeature(existing_features);
    
    dprintf("ShellCode feature added successfully:\n");
    dprintf("  Name: %s\n", shellcode_name);
    dprintf("  Base: 0x%08X\n", shellcode_base);
    dprintf("  Size: 0x%08X\n", shellcode_size);
    dprintf("  Feature Offset: 0x%08X\n", feature_offset);
    dprintf("  Feature Size: 0x%08X\n", feature_size);
    
    MessageBoxA(hwndDlg, "ShellCode feature added successfully", "Success", MB_ICONINFORMATION);
}

struct ViewFeaturesDialogData {
    std::vector<UserCustomShellCode>* features;
    bool modified;
};

INT_PTR CALLBACK ViewFeaturesDlgProc(HWND dlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
    {
        ViewFeaturesDialogData* data = (ViewFeaturesDialogData*)lParam;
        SetWindowLongPtr(dlg, GWLP_USERDATA, lParam);
        
        HWND hList = GetDlgItem(dlg, IDC_LIST_FEATURES);
        
        ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        
        LVCOLUMNA col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        
        col.pszText = (LPSTR)"Name";
        col.cx = 150;
        ListView_InsertColumn(hList, 0, &col);
        
        col.pszText = (LPSTR)"Size";
        col.cx = 80;
        ListView_InsertColumn(hList, 1, &col);
        
        col.pszText = (LPSTR)"Offset";
        col.cx = 80;
        ListView_InsertColumn(hList, 2, &col);
        
        col.pszText = (LPSTR)"Feature Bytes";
        col.cx = 280;
        ListView_InsertColumn(hList, 3, &col);
        
        for (size_t i = 0; i < data->features->size(); i++) {
            const auto& feature = data->features->at(i);
            
            std::string name = WideToUtf8(feature.name);
            char nameBuf[256];
            strcpy_s(nameBuf, name.c_str());
            
            LVITEMA item = {0};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = (int)i;
            item.lParam = (LPARAM)i;
            item.pszText = nameBuf;
            int idx = ListView_InsertItem(hList, &item);
            
            char buf[256];
            sprintf_s(buf, "0x%08X", feature.size);
            ListView_SetItemText(hList, idx, 1, buf);
            
            sprintf_s(buf, "0x%08X", feature.feature.feature_offset);
            ListView_SetItemText(hList, idx, 2, buf);
            
            std::string bytes = BufferToLine(feature.feature.feature_code);
            if (bytes.length() > 40) {
                bytes = bytes.substr(0, 40) + "...";
            }
            strcpy_s(buf, bytes.c_str());
            ListView_SetItemText(hList, idx, 3, buf);
        }
        
        break;
    }
    
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BTN_DELETE:
        {
            ViewFeaturesDialogData* data = (ViewFeaturesDialogData*)GetWindowLongPtr(dlg, GWLP_USERDATA);
            HWND hList = GetDlgItem(dlg, IDC_LIST_FEATURES);
            
            int sel = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
            if (sel == -1) {
                MessageBoxA(dlg, "Please select a feature to delete", "Info", MB_ICONINFORMATION);
                break;
            }
            
            LVITEMA item = {0};
            item.mask = LVIF_PARAM;
            item.iItem = sel;
            ListView_GetItem(hList, &item);
            int idx = (int)item.lParam;
            
            std::string name = WideToUtf8(data->features->at(idx).name);
            std::string msg = FormatString("Delete feature: %s?", name.c_str());
            
            if (IDYES == MessageBoxA(dlg, msg.c_str(), "Confirm Delete", MB_YESNO | MB_ICONQUESTION)) {
                data->features->erase(data->features->begin() + idx);
                ListView_DeleteItem(hList, sel);
                data->modified = true;
                
                for (int i = sel; i < ListView_GetItemCount(hList); i++) {
                    LVITEMA updateItem = {0};
                    updateItem.mask = LVIF_PARAM;
                    updateItem.iItem = i;
                    ListView_GetItem(hList, &updateItem);
                    updateItem.lParam = updateItem.lParam - 1;
                    ListView_SetItem(hList, &updateItem);
                }
            }
            break;
        }
        
        case IDC_BTN_CLOSE:
        case IDCANCEL:
            EndDialog(dlg, IDOK);
            break;
        }
        break;
        
    case WM_CLOSE:
        EndDialog(dlg, IDCANCEL);
        break;
    
    default:
        break;
    }
    
    return 0;
}

void ViewShellCodeFeatures()
{
    dputs("ViewShellCodeFeatures called");
    
    auto features = LoadUserCustomShellCodeFeature();
    
    dprintf("Loaded %d features\n", features.size());
    
    if (features.empty()) {
        dputs("No features found, showing message box");
        MessageBoxA(hwndDlg, "No shellcode features found in configuration file", "Info", MB_ICONINFORMATION);
        return;
    }
    
    ViewFeaturesDialogData data;
    data.features = &features;
    data.modified = false;
    
    dprintf("g_cur_dll_instalce = %p, hwndDlg = %p\n", g_cur_dll_instalce, hwndDlg);
    dputs("Showing dialog...");
    
    INT_PTR result = DialogBoxParam(g_cur_dll_instalce, MAKEINTRESOURCE(IDD_DIALOG_VIEW_FEATURES), hwndDlg, ViewFeaturesDlgProc, (LPARAM)&data);
    
    dprintf("Dialog result: %d\n", result);
    
    if (data.modified) {
        SaveUserCustomShellCodeFeature(features);
        dputs("ShellCode features saved");
    }
}


bool cbRemoveAllVirtualModCommand(int argc, char** argv)
{
    ListInfo module_list;
    if (!Script::Module::GetList(&module_list)) {
        dputs("Failed to get module list");
        return false;
    }

    std::vector<Script::Module::ModuleInfo> modules;
    BridgeList<Script::Module::ModuleInfo>::ToVector(&module_list, modules, true);

    int unload_count = 0;
    int failed_count = 0;

    dputs("Scanning for virtual modules...");

    for (const auto& mod : modules) {
        if (strncmp(mod.path, "virtual:\\", 9) == 0) {
            const char* module_name = mod.path + 9;
            
            char cmd[512];
            sprintf_s(cmd, "virtualmoddel %s", module_name);
            
            if (DbgCmdExecDirect(cmd)) {
                dprintf("Unloaded: %s\n", module_name);
                unload_count++;
            }
            else {
                dprintf("Failed: %s\n", module_name);
                failed_count++;
            }
        }
    }

    dprintf("Unloaded %d virtual module(s), %d failed\n", unload_count, failed_count);

    if (unload_count > 0) {
        GuiUpdateAllViews();
    }
    
    return true;
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