// main.cpp
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <iomanip>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <richedit.h> 
#include "xxhash.h"   

// --- Link Libraries ---
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Riched20.lib") 

// =============================================================
// FIX: STRUCT and ENUM Definitions MUST be declared before use!
// =============================================================

// --- Structures & Enum ---
struct FileEntry {
    std::string path;
    std::string hash;
};

enum class HashType {
    NONE,
    CRC32,
    XXH3
};

// --- Global UI Handles (unchanged) ---
HWND g_hProgressGlobal, g_hProgressFile, g_hLabelFile, g_hLogBox;
HWND g_hBtnStart, g_hBtnExit;
std::atomic<bool> g_IsRunning(false);

// --- Global Counters (unchanged) ---
std::atomic<int> g_CountOk(0);
std::atomic<int> g_CountCorrupted(0);
std::atomic<int> g_CountMissing(0);

// --- Helpers (unchanged) ---
std::string ToLower(const std::string &s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

std::string NormalizeHash(const std::string &h) {
    std::string s = ToLower(h);
    if (s.rfind("0x", 0) == 0)
        s = s.substr(2);
    s.erase(0, s.find_first_not_of('0'));
    return s.empty() ? "0" : s;
}

// --- Append Log (Rich Edit Version with Color - UNCHANGED) ---
void AppendLog(const std::string &text, COLORREF color) {
    // Conversion std::string -> std::wstring
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.length(), NULL, 0);
    std::wstring wtext(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), (int)text.length(), &wtext[0], size_needed);
    
    std::wstring wline = wtext + L"\r\n";
    
    // 1. Set the caret to the end of the text
    DWORD len = GetWindowTextLengthW(g_hLogBox);
    SendMessage(g_hLogBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);

    // 2. Define the character format (color)
    CHARFORMAT2W cf = {}; 
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    
    // 3. Apply the format (color)
    SendMessage(g_hLogBox, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

    // 4. Insert the text
    SendMessageW(g_hLogBox, EM_REPLACESEL, FALSE, (LPARAM)wline.c_str());

    // 5. Scroll to the bottom
    SendMessage(g_hLogBox, WM_VSCROLL, SB_BOTTOM, 0);
}

// --- CRC32 table (unchanged) ---
uint32_t crc32_table[256];
void MakeCrcTable() {
    const uint32_t POLY = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (POLY ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}

// --- Verify File (NOW COMPILES CORRECTLY) ---
std::string VerifyFile(const FileEntry &item, HashType hashType, std::atomic<int> &fileProgress, uint64_t &fileSize) {
    namespace fs = std::filesystem;
    if (!fs::exists(item.path)) {
        g_CountMissing++;
        return "MISSING"; 
    }

    try {
        fileSize = fs::file_size(item.path);
    } catch (const fs::filesystem_error& e) {
        fileSize = 0; 
        g_CountCorrupted++;
        return "ERROR_SIZE"; 
    }

    std::ifstream f(item.path, std::ios::binary);
    if (!f.is_open()) {
        g_CountCorrupted++;
        return "ERROR_OPEN"; 
    }

    const size_t BUF = 64 * 1024;
    std::vector<char> buffer(BUF);
    size_t readTotal = 0;

    int progressRange = (int)(fileSize / 1024);
    if (progressRange == 0 && fileSize > 0) progressRange = 1; 
    if (progressRange == 0) progressRange = 100;

    SendMessage(g_hProgressFile, PBM_SETRANGE, 0, MAKELPARAM(0, progressRange));

    std::string result = "ERROR_UNKNOWN";

    if (hashType == HashType::CRC32) {
        uint32_t crc = 0xFFFFFFFFu;
        while (f) {
            f.read(buffer.data(), BUF);
            std::streamsize r = f.gcount();
            if (r == 0) break;
            for (int i = 0; i < r; i++)
                crc = (crc >> 8) ^ crc32_table[(crc ^ (uint8_t)buffer[i]) & 0xFF];
            readTotal += r;
            fileProgress = (int)(readTotal / 1024);
            SendMessage(g_hProgressFile, PBM_SETPOS, fileProgress, 0);
            if (!g_IsRunning) return "CANCELED";
        }
        crc ^= 0xFFFFFFFFu;
        std::ostringstream oss;
        oss << std::hex << std::setw(8) << std::setfill('0') << crc;
        result = NormalizeHash(oss.str()) == NormalizeHash(item.hash) ? "OK" : "CORRUPTED";
    }
    else if (hashType == HashType::XXH3) {
        XXH3_state_t *state = XXH3_createState();
        if (!state) return "ERROR_XXH_INIT";
        
        XXH3_64bits_reset(state);
        while (f) {
            f.read(buffer.data(), BUF);
            std::streamsize r = f.gcount();
            if (r == 0) break;
            XXH3_64bits_update(state, buffer.data(), r);
            readTotal += r;
            fileProgress = (int)(readTotal / 1024);
            SendMessage(g_hProgressFile, PBM_SETPOS, fileProgress, 0);
            if (!g_IsRunning) {
                XXH3_freeState(state);
                return "CANCELED";
            }
        }
        
        uint64_t h = XXH3_64bits_digest(state);
        XXH3_freeState(state);
        std::ostringstream oss;
        oss << std::hex << std::setw(16) << std::setfill('0') << h;
        result = NormalizeHash(oss.str()) == NormalizeHash(item.hash) ? "OK" : "CORRUPTED";
    }
    
    if (result == "OK") {
        g_CountOk++;
    } else if (result == "CORRUPTED" || result.rfind("ERROR", 0) == 0) {
        g_CountCorrupted++;
    }

    return result;
}

// --- Load CRC (NOW COMPILES CORRECTLY) ---
bool LoadCRC(const std::string &filename, std::vector<FileEntry> &outFiles, HashType &outHashType) {
    std::ifstream f(filename);
    if (!f.is_open()) return false;

    if (filename.find(".xxhash3") != std::string::npos)
        outHashType = HashType::XXH3;
    else if (filename.find(".crc32") != std::string::npos)
        outHashType = HashType::CRC32;
    else
        return false; 

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string h, p;
        iss >> h;
        std::getline(iss, p);
        p.erase(std::remove(p.begin(), p.end(), '*'), p.end());
        p.erase(0, p.find_first_not_of(" \t"));
        outFiles.push_back({p, h});
    }
    return true;
}

// --- Report Generator (unchanged) ---
void GenerateReport(int total) {
    if (total == 0) {
        AppendLog("\n--- FINAL REPORT (0 files) ---", RGB(0, 0, 0));
        return;
    }

    int ok = g_CountOk;
    int corrupted = g_CountCorrupted;
    int missing = g_CountMissing;
    
    double p_ok = (double)ok / total * 100.0;
    double p_corrupted = (double)corrupted / total * 100.0;
    double p_missing = (double)missing / total * 100.0;

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);

    AppendLog("\n--- FINAL REPORT ---", RGB(0, 0, 0));
    AppendLog("Total Files: " + std::to_string(total), RGB(0, 0, 0));

    // Green
    oss.str(""); oss.clear();
    oss << "OK (Green): " << ok << " files (" << p_ok << "%)";
    AppendLog(oss.str(), RGB(0, 150, 0)); 

    // Red
    oss.str(""); oss.clear();
    oss << "CORRUPTED (Red): " << corrupted << " files (" << p_corrupted << "%)";
    AppendLog(oss.str(), RGB(200, 0, 0)); 

    // Yellow
    oss.str(""); oss.clear();
    oss << "MISSING (Yellow): " << missing << " files (" << p_missing << "%)";
    AppendLog(oss.str(), RGB(255, 165, 0)); 
}


// --- Worker Thread (NOW COMPILES CORRECTLY) ---
void Worker() {
    g_CountOk = 0;
    g_CountCorrupted = 0;
    g_CountMissing = 0;
    
    MakeCrcTable();
    std::vector<FileEntry> files; // FileEntry and HashType are now known
    HashType hashType = HashType::NONE;

    std::vector<std::string> candidates = {"CRC.xxhash3", "CRC.crc32"};
    bool fileFound = false;
    std::string loadedFile = "";

    for (auto &c : candidates) {
        if (std::filesystem::exists(c)) {
            if (LoadCRC(c, files, hashType)) {
                fileFound = true;
                loadedFile = c;
                break;
            }
        }
    }

    if (!fileFound) {
        AppendLog("ERROR: No supported CRC file (XXH3 or CRC32) found!", RGB(200, 0, 0));
        g_IsRunning = false;
        SetWindowTextW(g_hBtnStart, TEXT("Start"));
        return;
    }
    
    AppendLog("CRC file loaded: " + loadedFile, RGB(0, 0, 0));

    int total = (int)files.size();
    if (total == 0) {
        AppendLog("The CRC file is empty!", RGB(200, 0, 0));
        g_IsRunning = false;
        SetWindowTextW(g_hBtnStart, TEXT("Start"));
        return;
    }

    SendMessage(g_hProgressGlobal, PBM_SETRANGE, 0, MAKELPARAM(0, total));
    int i = 0;

    for (auto &f : files) { // 'files' is now recognized as std::vector<FileEntry>
        if (!g_IsRunning) break;

        std::atomic<int> fileProgress(0);
        uint64_t fileSize = 0;
        
        SetWindowTextA(g_hLabelFile, f.path.c_str());

        std::string status = VerifyFile(f, hashType, fileProgress, fileSize);
        
        COLORREF statusColor;
        std::string statusPrefix;

        if (status == "OK") {
            statusPrefix = "[✓] ";
            statusColor = RGB(0, 150, 0); // Green
        } else if (status == "CORRUPTED" || status.rfind("ERROR", 0) == 0) {
            statusPrefix = "[✗] ";
            statusColor = RGB(200, 0, 0); // Red
        } else if (status == "MISSING") {
            statusPrefix = "[?] ";
            statusColor = RGB(255, 165, 0); // Yellow/Orange
        } else if (status == "CANCELED") {
            break; 
        } else {
            statusPrefix = "[!] ";
            statusColor = RGB(200, 0, 0); 
        }

        std::string logLine = statusPrefix + f.path + " - " + status;
        AppendLog(logLine, statusColor);

        SendMessage(g_hProgressGlobal, PBM_SETPOS, ++i, 0);
    }
    
    // Finalization
    if (g_IsRunning) {
        SetWindowTextW(g_hLabelFile, TEXT("FINISHED!"));
        AppendLog("\n✓ Verification process finished!", RGB(0, 150, 0));
        GenerateReport(total);
    } else {
        SetWindowTextW(g_hLabelFile, TEXT("CANCELED!"));
        AppendLog("\n! Process canceled!", RGB(200, 0, 0));
    }
    
    SendMessage(g_hProgressFile, PBM_SETPOS, 0, 0);
    
    g_IsRunning = false;
    SetWindowTextW(g_hBtnStart, TEXT("Start"));
}

// --- Window Procedure (unchanged) ---
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 1: // Start/Stop
            if (!g_IsRunning) {
                // CLEAR LOG: Set selection to all (-1) and replace with empty string
                SendMessage(g_hLogBox, EM_SETSEL, 0, -1); 
                SendMessage(g_hLogBox, EM_REPLACESEL, 0, (LPARAM)L""); 
                
                g_IsRunning = true;
                std::thread(Worker).detach();
                SetWindowTextW(g_hBtnStart, TEXT("Stop"));
            } else {
                g_IsRunning = false; 
            }
            break;
        case 2: // Exit
            if (!g_IsRunning) DestroyWindow(hwnd);
            break;
        }
        break;
    case WM_CLOSE:
        if (!g_IsRunning) DestroyWindow(hwnd);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// --- WinMain (unchanged) ---
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    // 1. Initialisation du Rich Edit (inchangée)
    HMODULE hRichedit = LoadLibrary(TEXT("Msftedit.dll")); 
    if (!hRichedit) {
        hRichedit = LoadLibrary(TEXT("riched20.dll"));
        if (!hRichedit) {
            MessageBoxW(NULL, L"Failed to load RichEdit library! Log coloring might fail.", L"Error", MB_ICONERROR);
        }
    }

    // 2. Traitement des arguments de ligne de commande
    bool startImmediately = false;
    int nArgs;
    LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);

    if (szArglist) {
        // Commencer à 1 pour ignorer le nom de l'exécutable (szArglist[0])
        for (int i = 1; i < nArgs; i++) {
            // Comparer l'argument avec "-v" ou "/v" (sans distinction de casse)
            if ( (lstrcmpiW(szArglist[i], L"-v") == 0) || 
                 (lstrcmpiW(szArglist[i], L"/v") == 0) ) 
            {
                startImmediately = true;
                break;
            }
        }
        // Libérer la mémoire allouée par CommandLineToArgvW
        LocalFree(szArglist);
    }

    // 3. Initialisation de la fenêtre (inchangée)
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc = {}; 
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"MainWin";

    if (!RegisterClassW(&wc)) return 0; 

    HWND hwnd = CreateWindowExW(0, L"MainWin", L"NewCrc v0.1", WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 500, nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 0;

    // Création des contrôles (inchangée)
    // ... (omission des CreateWindowExW pour les boutons/progress bars pour la concision)
    g_hLabelFile = CreateWindowExW(0, TEXT("STATIC"), TEXT("File..."), WS_CHILD | WS_VISIBLE, 10, 10, 660, 25, hwnd, nullptr, hInst, nullptr);
    LPCWSTR richEditClassName = hRichedit ? L"RICHEDIT50W" : L"EDIT"; 
    g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, richEditClassName, L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 10, 40, 660, 320, hwnd, nullptr, hInst, nullptr);
    if (hRichedit && !g_hLogBox) {
        richEditClassName = L"RICHEDIT_CLASSW";
        g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, richEditClassName, L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 10, 40, 660, 320, hwnd, nullptr, hInst, nullptr);
    }
    g_hProgressFile = CreateWindowExW(0, PROGRESS_CLASS, nullptr, WS_CHILD | WS_VISIBLE, 10, 370, 450, 20, hwnd, nullptr, hInst, nullptr);
    g_hProgressGlobal = CreateWindowExW(0, PROGRESS_CLASS, nullptr, WS_CHILD | WS_VISIBLE, 10, 400, 660, 20, hwnd, nullptr, hInst, nullptr);
    g_hBtnStart = CreateWindowExW(0, TEXT("BUTTON"), TEXT("Start"), WS_CHILD | WS_VISIBLE, 480, 370, 90, 25, hwnd, (HMENU)1, hInst, nullptr);
    g_hBtnExit = CreateWindowExW(0, TEXT("BUTTON"), TEXT("Exit"), WS_CHILD | WS_VISIBLE, 580, 370, 90, 25, hwnd, (HMENU)2, hInst, nullptr);


    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // 4. Démarrage automatique si l'argument est trouvé
    if (startImmediately) {
        // Le code de démarrage est le même que le bouton "Start"
        // Nous effaçons le log, démarrons le thread Worker et changeons le texte du bouton.
        SendMessage(g_hLogBox, EM_SETSEL, 0, -1); 
        SendMessage(g_hLogBox, EM_REPLACESEL, 0, (LPARAM)L""); 
        
        g_IsRunning = true;
        std::thread(Worker).detach();
        SetWindowTextW(g_hBtnStart, TEXT("Stop"));
    }

    // 5. Boucle de messages (inchangée)
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (hRichedit) FreeLibrary(hRichedit);
    
    return (int)msg.wParam;
}