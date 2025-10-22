/**
 * @file main.cpp
 * @version 0.9 (Optimized - No std::format)
 */

#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <memory>
#include <mutex>
#include <iomanip>

#include "xxhash.h"
#include "city.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Riched20.lib")

#define WM_APP_UPDATE_FILE_PROGRESS   (WM_APP + 1)
#define WM_APP_UPDATE_GLOBAL_PROGRESS (WM_APP + 2)
#define WM_APP_APPEND_LOG             (WM_APP + 3)
#define WM_APP_TASK_COMPLETE          (WM_APP + 4)
#define WM_APP_TASK_ERROR             (WM_APP + 5)

struct FileProgressData {
    std::wstring filename;
    int percentage;
};

struct LogData {
    std::wstring text;
    COLORREF color;
};

struct TaskCompleteData {
    int totalFiles;
    long long duration_s;
    bool wasCanceled;
};

struct FileEntry {
    std::string path;
    std::string expectedHash;
};

enum class HashType { NONE, CRC32, XXH3, CITY128 };
enum class VerifyStatus { OK, CORRUPTED, MISSING, ERROR_SIZE, ERROR_OPEN, CANCELED, ERROR_UNSUPPORTED_HASH };

HWND g_hMainWindow, g_hProgressGlobal, g_hProgressFile, g_hLogBox;
HWND g_hBtnStart, g_hBtnExit, g_hLabelGlobalProgress, g_hLabelFileProgress;

std::atomic<bool> g_stopRequested{false};
std::atomic<bool> g_isRunning{false};
std::vector<std::jthread> g_workers;

std::atomic<int> g_CountOk{0}, g_CountCorrupted{0}, g_CountMissing{0};
std::atomic<size_t> g_nextFileIndex{0};
std::atomic<int> g_filesProcessedCount{0};

std::mutex g_uiMutex;
std::chrono::steady_clock::time_point g_lastUIUpdate;
const int UI_UPDATE_INTERVAL_MS = 500;

uint32_t crc32_table[256];
std::once_flag g_crcTableFlag;

std::wstring s2ws(std::string_view s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.length()), nullptr, 0);
    if (len == 0) return L"";
    std::wstring r(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.length()), &r[0], len);
    return r;
}

std::string GetFileName(std::string_view path) {
    return std::filesystem::path(path).filename().string();
}

std::string NormalizeHash(std::string_view h) {
    std::string s(h);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s.size() >= 2 && s[0] == '0' && s[1] == 'x') s = s.substr(2);
    s.erase(0, s.find_first_not_of('0'));
    return s.empty() ? "0" : s;
}

void MakeCrcTable() {
    const uint32_t POLY = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) 
            c = (c & 1) ? (POLY ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}

bool ShouldUpdateUI() {
    std::lock_guard<std::mutex> lock(g_uiMutex);
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastUIUpdate).count() >= UI_UPDATE_INTERVAL_MS) {
        g_lastUIUpdate = now;
        return true;
    }
    return false;
}

VerifyStatus VerifyFile(const FileEntry &item, HashType hashType, uint64_t &fileSize) {
    namespace fs = std::filesystem;
    std::string filename = GetFileName(item.path);

    auto post_progress = [&](int percentage, bool force = false) {
        if (!force && !ShouldUpdateUI()) return;
        auto data = std::make_unique<FileProgressData>(s2ws(filename), percentage);
        PostMessage(g_hMainWindow, WM_APP_UPDATE_FILE_PROGRESS, 0, (LPARAM)data.release());
    };

    post_progress(0, true);

    if (!fs::exists(item.path)) {
        g_CountMissing++;
        return VerifyStatus::MISSING;
    }

    try {
        fileSize = fs::file_size(item.path);
    } catch (const fs::filesystem_error&) {
        g_CountCorrupted++;
        return VerifyStatus::ERROR_SIZE;
    }

    std::ifstream f(item.path, std::ios::binary);
    if (!f.is_open()) {
        g_CountCorrupted++;
        return VerifyStatus::ERROR_OPEN;
    }

    const size_t BUF_SIZE = 8 * 1024 * 1024;
    std::vector<char> buffer(BUF_SIZE);
    uint64_t readTotal = 0;
    std::string resultHash;

    auto update_logic = [&](std::streamsize bytesRead) {
        readTotal += bytesRead;
        int pct = (fileSize > 0) ? (int)(readTotal * 100 / fileSize) : 0;
        post_progress(pct);
    };

    switch (hashType) {
        case HashType::CRC32: {
            uint32_t crc = 0xFFFFFFFFu;
            while (f && !g_stopRequested) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                for (int i = 0; i < r; ++i) 
                    crc = (crc >> 8) ^ crc32_table[(crc ^ (uint8_t)buffer[i]) & 0xFF];
                update_logic(r);
            }
            if (g_stopRequested) return VerifyStatus::CANCELED;
            crc ^= 0xFFFFFFFFu;
            
            std::ostringstream oss;
            oss << std::hex << std::setfill('0') << std::setw(8) << crc;
            resultHash = oss.str();
            break;
        }
        case HashType::XXH3: {
            XXH3_state_t* state = XXH3_createState();
            XXH3_64bits_reset(state);
            while (f && !g_stopRequested) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                XXH3_64bits_update(state, buffer.data(), r);
                update_logic(r);
            }
            if (g_stopRequested) {
                XXH3_freeState(state);
                return VerifyStatus::CANCELED;
            }
            uint64_t h = XXH3_64bits_digest(state);
            XXH3_freeState(state);
            
            std::ostringstream oss;
            oss << std::hex << std::setfill('0') << std::setw(16) << h;
            resultHash = oss.str();
            break;
        }
        case HashType::CITY128: {
            std::vector<char> fileContent;
            fileContent.reserve(fileSize);
            while (f && !g_stopRequested) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                fileContent.insert(fileContent.end(), buffer.data(), buffer.data() + r);
                update_logic(r);
            }
            if (g_stopRequested) return VerifyStatus::CANCELED;
            uint128 hash128 = CityHash128(fileContent.data(), fileContent.size());
            
            std::ostringstream oss;
            oss << std::hex << std::setfill('0') << std::setw(16) << Uint128High64(hash128)
                << std::setw(16) << Uint128Low64(hash128);
            resultHash = oss.str();
            break;
        }
        default: return VerifyStatus::ERROR_UNSUPPORTED_HASH;
    }

    VerifyStatus status = (NormalizeHash(resultHash) == NormalizeHash(item.expectedHash)) 
                          ? VerifyStatus::OK : VerifyStatus::CORRUPTED;
    
    if (status == VerifyStatus::OK) g_CountOk++;
    else g_CountCorrupted++;
    
    post_progress(100, true);
    return status;
}

bool LoadManifest(const std::filesystem::path& manifestPath, std::vector<FileEntry> &outFiles, HashType &outHashType) {
    std::ifstream f(manifestPath);
    if (!f.is_open()) return false;

    std::string ext = manifestPath.extension().string();
    if (ext == ".xxhash3") outHashType = HashType::XXH3;
    else if (ext == ".crc32") outHashType = HashType::CRC32;
    else if (ext == ".city128") outHashType = HashType::CITY128;
    else return false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || (line.size() > 0 && line[0] == ';')) continue;
        std::istringstream iss(line);
        std::string hash, path;
        iss >> hash;
        std::getline(iss, path);
        path.erase(0, path.find_first_not_of(" *"));
        if (!path.empty()) outFiles.push_back({path, hash});
    }
    return true;
}

void HashWorker(const std::vector<FileEntry>* files, HashType hashType, int totalFiles) {
    while (!g_stopRequested) {
        size_t currentIndex = g_nextFileIndex.fetch_add(1);
        if (currentIndex >= (size_t)totalFiles) break;

        const FileEntry& f = (*files)[currentIndex];
        uint64_t fileSize = 0;

        VerifyStatus status = VerifyFile(f, hashType, fileSize);
        if (status == VerifyStatus::CANCELED) break;
        
        int processedCount = g_filesProcessedCount.fetch_add(1) + 1;
        PostMessage(g_hMainWindow, WM_APP_UPDATE_GLOBAL_PROGRESS, processedCount, totalFiles);

        COLORREF color = (status == VerifyStatus::OK) ? RGB(0, 150, 0) : 
                        (status == VerifyStatus::MISSING) ? RGB(255, 165, 0) : RGB(200, 0, 0);
        
        std::string statusStr = (status == VerifyStatus::OK) ? "OK" : 
                               (status == VerifyStatus::CORRUPTED) ? "CORRUPTED" : 
                               (status == VerifyStatus::MISSING) ? "MISSING" : "ERROR";

        std::string logLine = f.path + " - " + statusStr;
        auto logData = std::make_unique<LogData>(s2ws(logLine), color);
        PostMessage(g_hMainWindow, WM_APP_APPEND_LOG, 0, (LPARAM)logData.release());
    }
}

void ManagerThread() {
    g_CountOk = 0; g_CountCorrupted = 0; g_CountMissing = 0;
    g_nextFileIndex = 0; g_filesProcessedCount = 0;
    g_stopRequested = false;
    std::call_once(g_crcTableFlag, MakeCrcTable);

    auto post_log = [](const std::string& text, COLORREF color) {
        auto data = std::make_unique<LogData>(s2ws(text), color);
        PostMessage(g_hMainWindow, WM_APP_APPEND_LOG, 0, (LPARAM)data.release());
    };

    auto files = std::make_unique<std::vector<FileEntry>>();
    HashType hashType = HashType::NONE;
    std::vector<std::filesystem::path> candidates = {"CRC.xxhash3", "CRC.crc32", "CRC.city128"};
    std::string loadedFile;

    for (const auto &c : candidates) {
        if (std::filesystem::exists(c)) {
            if (LoadManifest(c, *files, hashType)) {
                loadedFile = c.string();
                break;
            }
        }
    }

    if (loadedFile.empty()) {
        auto err = std::make_unique<LogData>(L"Error: No manifest found.", RGB(200,0,0));
        PostMessage(g_hMainWindow, WM_APP_TASK_ERROR, 0, (LPARAM)err.release());
        g_isRunning = false;
        return;
    }
    
    post_log("Manifest: " + loadedFile, RGB(0,0,0));
    int totalFiles = files->size();

    if (totalFiles == 0) {
        auto err = std::make_unique<LogData>(L"Error: Empty manifest.", RGB(200,0,0));
        PostMessage(g_hMainWindow, WM_APP_TASK_ERROR, 0, (LPARAM)err.release());
        g_isRunning = false;
        return;
    }

    PostMessage(g_hMainWindow, WM_APP_UPDATE_GLOBAL_PROGRESS, 0, totalFiles);
    auto startTime = std::chrono::steady_clock::now();

    unsigned int num_threads = std::min(std::thread::hardware_concurrency(), 4u);
    if (num_threads == 0) num_threads = 2;
    
    g_workers.clear();
    for (unsigned int i = 0; i < num_threads; ++i) {
        g_workers.emplace_back(HashWorker, files.get(), hashType, totalFiles);
    }

    for (auto& t : g_workers) {
        if (t.joinable()) t.join();
    }
    g_workers.clear();

    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
    
    auto completionData = std::make_unique<TaskCompleteData>(totalFiles, duration, g_stopRequested.load());
    PostMessage(g_hMainWindow, WM_APP_TASK_COMPLETE, 0, (LPARAM)completionData.release());
    
    g_isRunning = false;
}

void AppendLog_UI(const std::wstring &wline, COLORREF color) {
    DWORD len = GetWindowTextLengthW(g_hLogBox);
    SendMessage(g_hLogBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    CHARFORMAT2W cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessage(g_hLogBox, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    SendMessageW(g_hLogBox, EM_REPLACESEL, FALSE, (LPARAM)(wline + L"\r\n").c_str());
    SendMessage(g_hLogBox, WM_VSCROLL, SB_BOTTOM, 0);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_APP_UPDATE_FILE_PROGRESS: {
            auto data = std::unique_ptr<FileProgressData>(reinterpret_cast<FileProgressData*>(lParam));
            std::wstring text = L"File: " + data->filename + L" - " + std::to_wstring(data->percentage) + L"%";
            SetWindowTextW(g_hLabelFileProgress, text.c_str());
            SendMessage(g_hProgressFile, PBM_SETPOS, data->percentage, 0);
            break;
        }

        case WM_APP_UPDATE_GLOBAL_PROGRESS: {
            int current = (int)wParam;
            int total = (int)lParam;
            int pct = (total > 0) ? (current * 100 / total) : 0;
            std::wstring text = L"Progress: " + std::to_wstring(current) + L"/" + 
                               std::to_wstring(total) + L" (" + std::to_wstring(pct) + L"%)";
            SetWindowTextW(g_hLabelGlobalProgress, text.c_str());
            SendMessage(g_hProgressGlobal, PBM_SETRANGE32, 0, total);
            SendMessage(g_hProgressGlobal, PBM_SETPOS, current, 0);
            break;
        }

        case WM_APP_APPEND_LOG: {
            auto data = std::unique_ptr<LogData>(reinterpret_cast<LogData*>(lParam));
            AppendLog_UI(data->text, data->color);
            break;
        }
        
        case WM_APP_TASK_ERROR: {
            auto data = std::unique_ptr<LogData>(reinterpret_cast<LogData*>(lParam));
            AppendLog_UI(data->text, data->color);
            SetWindowTextW(g_hBtnStart, L"Start");
            break;
        }
        
        case WM_APP_TASK_COMPLETE: {
            auto data = std::unique_ptr<TaskCompleteData>(reinterpret_cast<TaskCompleteData*>(lParam));
            
            SetWindowTextW(g_hLabelFileProgress, L"File: Ready");
            SendMessage(g_hProgressFile, PBM_SETPOS, 0, 0);
            
            if (!data->wasCanceled) {
                std::wstring report = L"Completed: " + std::to_wstring(g_CountOk.load()) + L"/" + 
                                     std::to_wstring(g_CountCorrupted.load()) + L"/" + 
                                     std::to_wstring(g_CountMissing.load()) + 
                                     L" (OK/ERR/MISS) in " + std::to_wstring(data->duration_s) + L" sec";
                AppendLog_UI(report, RGB(0, 150, 0));
            } else {
                AppendLog_UI(L"Canceled by user.", RGB(200, 0, 0));
            }
            
            SetWindowTextW(g_hBtnStart, L"Start");
            break;
        }

        case WM_COMMAND:
            if (LOWORD(wParam) == 1) {
                if (!g_isRunning) {
                    SendMessage(g_hLogBox, WM_SETTEXT, 0, (LPARAM)L"");
                    g_isRunning = true;
                    std::thread(ManagerThread).detach();
                    SetWindowTextW(g_hBtnStart, L"Stop");
                } else {
                    g_stopRequested = true;
                }
            } else if (LOWORD(wParam) == 2 && !g_isRunning) {
                DestroyWindow(hwnd);
            }
            break;

        case WM_CLOSE:
            if (!g_isRunning) DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            g_stopRequested = true;
            for (auto& t : g_workers) {
                if (t.joinable()) t.join();
            }
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    LoadLibrary(TEXT("Msftedit.dll"));
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"FileHasherWindowClass";
    RegisterClassW(&wc);

    g_hMainWindow = CreateWindowExW(0, L"FileHasherWindowClass", L"NewCrc 0.7.1-L", 
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 540, nullptr, nullptr, hInst, nullptr);

    if (!g_hMainWindow) return 1;

    g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"", 
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 
        10, 10, 660, 325, g_hMainWindow, nullptr, hInst, nullptr);
    g_hLabelFileProgress = CreateWindowExW(0, L"STATIC", L"File: Ready", 
        WS_CHILD | WS_VISIBLE, 10, 345, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hProgressFile = CreateWindowExW(0, PROGRESS_CLASS, nullptr, 
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 370, 450, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hLabelGlobalProgress = CreateWindowExW(0, L"STATIC", L"Progress: 0/0 (0%)", 
        WS_CHILD | WS_VISIBLE, 10, 400, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hProgressGlobal = CreateWindowExW(0, PROGRESS_CLASS, nullptr, 
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 425, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hBtnStart = CreateWindowExW(0, L"BUTTON", L"Start", 
        WS_CHILD | WS_VISIBLE, 480, 368, 90, 25, g_hMainWindow, (HMENU)1, hInst, nullptr);
    g_hBtnExit = CreateWindowExW(0, L"BUTTON", L"Exit", 
        WS_CHILD | WS_VISIBLE, 580, 368, 90, 25, g_hMainWindow, (HMENU)2, hInst, nullptr);

    int nArgs;
    LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist && nArgs > 1 && (lstrcmpiW(szArglist[1], L"-v") == 0)) {
        PostMessage(g_hMainWindow, WM_COMMAND, 1, 0);
    }
    LocalFree(szArglist);

    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return static_cast<int>(msg.wParam);
}