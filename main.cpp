/**
 * @file main.cpp
 * @brief Application Win32 multithread pour la vérification de l'intégrité de fichiers par hachage.
 * @version 0.5 (Professional Multithreaded)
 *
 * @details
 * Ce programme vérifie une liste de fichiers par rapport à leurs sommes de contrôle
 * (CRC32, XXH3, CityHash128) spécifiées dans un fichier manifeste.
 * L'architecture utilise un pool de threads pour paralléliser les calculs de hachage
 * et une communication asynchrone par messages Windows (PostMessage) pour mettre à jour
 * l'interface utilisateur sans la bloquer, garantissant une expérience fluide et réactive.
 */

// --- Inclusions Standards et Externes ---
#include <windows.h>
#include <commctrl.h>   // Pour les contrôles communs (barres de progression)
#include <richedit.h>   // Pour le contrôle Rich Edit (log coloré)
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <deque>

// --- Inclusions des bibliothèques de hachage ---
#include "xxhash.h"
#include "city.h"

// --- Liaison des bibliothèques Windows ---
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Riched20.lib")

// =================================================================================
// Section: Définitions et Structures Globales
// =================================================================================

// --- Messages personnalisés pour la communication inter-thread ---
// Utilisés pour découpler le thread de travail du thread UI.
#define WM_APP_UPDATE_FILE_PROGRESS   (WM_APP + 1) // Met à jour la progression d'un fichier unique
#define WM_APP_UPDATE_GLOBAL_PROGRESS (WM_APP + 2) // Met à jour la progression globale
#define WM_APP_APPEND_LOG             (WM_APP + 3) // Ajoute une ligne au log
#define WM_APP_TASK_COMPLETE          (WM_APP + 4) // Signale la fin de toutes les opérations
#define WM_APP_TASK_ERROR             (WM_APP + 5) // Signale une erreur critique de démarrage

/**
 * @struct FileProgressData
 * @brief Transporte les données de progression d'un fichier pour l'UI.
 * Alloué dans le thread worker, libéré dans le thread UI.
 */
struct FileProgressData {
    std::wstring filename;
    int percentage;
    double speed_MBps;
};

/**
 * @struct LogData
 * @brief Transporte le texte et la couleur pour un message de log.
 */
struct LogData {
    std::wstring text;
    COLORREF color;
};

/**
 * @struct TaskCompleteData
 * @brief Transporte les statistiques finales à la fin du processus.
 */
struct TaskCompleteData {
    int totalFiles;
    long long duration_s;
    bool wasCanceled;
};

/**
 * @struct FileEntry
 * @brief Représente un fichier à vérifier avec son hash attendu.
 */
struct FileEntry {
    std::string path;
    std::string expectedHash;
};

/**
 * @enum HashType
 * @brief Énumère les algorithmes de hachage supportés.
 */
enum class HashType { NONE, CRC32, XXH3, CITY128 };

// --- Handle de fenêtres et variables d'état globales ---
HWND g_hMainWindow;
HWND g_hProgressGlobal, g_hProgressFile, g_hLogBox;
HWND g_hBtnStart, g_hBtnExit;
HWND g_hLabelGlobalProgress, g_hLabelFileProgress;

/// @brief Contrôle l'état d'exécution des threads de travail.
std::atomic<bool> g_IsRunning(false);

// --- Compteurs atomiques pour les statistiques ---
std::atomic<int> g_CountOk(0);
std::atomic<int> g_CountCorrupted(0);
std::atomic<int> g_CountMissing(0);

// --- Synchronisation du pool de threads ---
/// @brief Index atomique du prochain fichier à traiter par le pool.
std::atomic<size_t> g_nextFileIndex(0);
/// @brief Compteur atomique du nombre de fichiers traités.
std::atomic<int> g_filesProcessedCount(0);


// =================================================================================
// Section: Fonctions Utilitaires
// =================================================================================

/**
 * @brief Calcule la vitesse de traitement en Mo/s sur une fenêtre glissante.
 */
struct SpeedBuffer {
    std::deque<std::pair<std::chrono::steady_clock::time_point, size_t>> samples;
    const size_t maxSamples = 10;
    
    void AddSample(size_t bytes) {
        samples.push_back({std::chrono::steady_clock::now(), bytes});
        if (samples.size() > maxSamples) samples.pop_front();
    }
    
    double GetSpeed() {
        if (samples.size() < 2) return 0.0;
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(samples.back().first - samples.front().first).count();
        if (duration == 0) return 0.0;
        size_t totalBytes = 0;
        for (size_t i = 1; i < samples.size(); ++i) totalBytes += samples[i].second;
        return (totalBytes / 1024.0 / 1024.0) / (duration / 1000.0);
    }
};

/**
 * @brief Convertit une chaîne UTF-8 (std::string) en UTF-16 (std::wstring).
 */
std::wstring s2ws(const std::string& s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (len == 0) return L"";
    std::wstring r(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &r[0], len);
    return r;
}

/**
 * @brief Extrait le nom de fichier d'un chemin complet.
 */
std::string GetFileName(const std::string &path) {
    size_t pos = path.find_last_of("\\/");
    return (pos != std::string::npos) ? path.substr(pos + 1) : path;
}

/**
 * @brief Formate une taille en octets en une chaîne lisible (Ko, Mo, Go).
 */
std::string FormatFileSize(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int i = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && i < 3) {
        size /= 1024;
        i++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[i];
    return oss.str();
}

/**
 * @brief Normalise une chaîne de hash (minuscules, sans "0x" ni zéros en tête).
 */
std::string NormalizeHash(const std::string &h) {
    std::string s = h;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s.rfind("0x", 0) == 0) s = s.substr(2);
    s.erase(0, s.find_first_not_of('0'));
    return s.empty() ? "0" : s;
}

/**
 * @brief Génère la table de lookup pour les calculs CRC32.
 */
uint32_t crc32_table[256];
void MakeCrcTable() {
    const uint32_t POLY = 0xEDB88320u;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c & 1) ? (POLY ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
}


// =================================================================================
// Section: Logique de Traitement des Fichiers (Threads Workers)
// =================================================================================

/**
 * @brief Vérifie un fichier unique en calculant son hash et en le comparant.
 * @details Cette fonction est conçue pour être exécutée par les threads workers.
 * Elle envoie des messages à l'UI pour rapporter sa progression.
 * @param item L'entrée de fichier à vérifier.
 * @param hashType L'algorithme de hash à utiliser.
 * @param[out] fileSize Taille du fichier en octets, déterminée par la fonction.
 * @return Une chaîne de caractères indiquant le statut ("OK", "CORRUPTED", "MISSING", etc.).
 */
std::string VerifyFile(const FileEntry &item, HashType hashType, uint64_t &fileSize) {
    namespace fs = std::filesystem;
    std::string filename = GetFileName(item.path);

    auto post_progress = [&](int percentage, double speed) {
        auto* data = new FileProgressData{ s2ws(filename), percentage, speed };
        PostMessage(g_hMainWindow, WM_APP_UPDATE_FILE_PROGRESS, 0, (LPARAM)data);
    };

    post_progress(0, 0.0);

    if (!fs::exists(item.path)) {
        g_CountMissing++;
        return "MISSING";
    }

    try {
        fileSize = fs::file_size(item.path);
    } catch (const fs::filesystem_error&) {
        g_CountCorrupted++;
        return "ERROR_SIZE";
    }

    std::ifstream f(item.path, std::ios::binary);
    if (!f.is_open()) {
        g_CountCorrupted++;
        return "ERROR_OPEN";
    }

    const size_t BUF_SIZE = 16 * 1024 * 1024; // Buffer de 16 Mo pour des I/O efficaces
    std::vector<char> buffer(BUF_SIZE);
    uint64_t readTotal = 0;
    SpeedBuffer speedBuffer;
    auto lastUpdate = std::chrono::steady_clock::now();
    std::string resultHash;

    auto update_logic = [&](std::streamsize bytesRead) {
        readTotal += bytesRead;
        speedBuffer.AddSample(bytesRead);
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - lastUpdate).count() >= 100) {
            post_progress((fileSize > 0) ? (int)(readTotal * 100 / fileSize) : 0, speedBuffer.GetSpeed());
            lastUpdate = now;
        }
    };

    switch (hashType) {
        case HashType::CRC32: {
            uint32_t crc = 0xFFFFFFFFu;
            while (f) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                for (int i = 0; i < r; ++i) crc = (crc >> 8) ^ crc32_table[(crc ^ (uint8_t)buffer[i]) & 0xFF];
                update_logic(r);
                if (!g_IsRunning) return "CANCELED";
            }
            crc ^= 0xFFFFFFFFu;
            std::ostringstream oss;
            oss << std::hex << std::setw(8) << std::setfill('0') << crc;
            resultHash = oss.str();
            break;
        }
        case HashType::XXH3: {
            XXH3_state_t* state = XXH3_createState();
            XXH3_64bits_reset(state);
            while (f) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                XXH3_64bits_update(state, buffer.data(), r);
                update_logic(r);
                if (!g_IsRunning) { XXH3_freeState(state); return "CANCELED"; }
            }
            uint64_t h = XXH3_64bits_digest(state);
            XXH3_freeState(state);
            std::ostringstream oss;
            oss << std::hex << std::setw(16) << std::setfill('0') << h;
            resultHash = oss.str();
            break;
        }
        case HashType::CITY128: {
            // Note: CityHash128 n'a pas d'API de streaming, ce qui peut consommer de la RAM pour les très gros fichiers.
            std::vector<char> fileContent;
            fileContent.reserve(fileSize);
            while (f) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                fileContent.insert(fileContent.end(), buffer.data(), buffer.data() + r);
                update_logic(r);
                if (!g_IsRunning) return "CANCELED";
            }
            uint128 hash128 = CityHash128(fileContent.data(), fileContent.size());
            std::ostringstream oss;
            oss << std::hex << std::setw(16) << std::setfill('0') << Uint128High64(hash128)
                << std::hex << std::setw(16) << std::setfill('0') << Uint128Low64(hash128);
            resultHash = oss.str();
            break;
        }
        default: return "ERROR_UNSUPPORTED_HASH";
    }

    std::string status = (NormalizeHash(resultHash) == NormalizeHash(item.expectedHash)) ? "OK" : "CORRUPTED";
    
    if (status == "OK") g_CountOk++;
    else g_CountCorrupted++;
    
    post_progress(100, speedBuffer.GetSpeed());
    return status;
}

/**
 * @brief Parse un fichier manifeste de sommes de contrôle.
 * @return `true` si le chargement et le parsing réussissent, `false` sinon.
 */
bool LoadManifest(const std::string &filename, std::vector<FileEntry> &outFiles, HashType &outHashType) {
    std::ifstream f(filename);
    if (!f.is_open()) return false;

    if (filename.find(".xxhash3") != std::string::npos) outHashType = HashType::XXH3;
    else if (filename.find(".crc32") != std::string::npos) outHashType = HashType::CRC32;
    else if (filename.find(".city128") != std::string::npos) outHashType = HashType::CITY128;
    else return false;

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == ';') continue; // Ignorer les lignes vides et les commentaires
        std::istringstream iss(line);
        std::string hash, path;
        iss >> hash;
        std::getline(iss, path);
        // Nettoyer le chemin
        if (!path.empty() && path[0] == ' ') path.erase(0, 1);
        if (!path.empty() && path[0] == '*') path.erase(0, 1);
        if (!path.empty()) outFiles.push_back({path, hash});
    }
    return true;
}


// =================================================================================
// Section: Logique de Multithreading
// =================================================================================

/**
 * @brief Fonction exécutée par chaque thread ouvrier du pool.
 * @details Chaque thread récupère itérativement un fichier à traiter depuis la liste
 * globale de manière atomique, le traite, puis rapporte le résultat.
 * @param files Pointeur vers le vecteur contenant tous les fichiers à traiter.
 * @param hashType L'algorithme de hash à utiliser.
 * @param totalFiles Le nombre total de fichiers dans la liste.
 */
void HashWorker(const std::vector<FileEntry>* files, HashType hashType, int totalFiles) {
    while (g_IsRunning) {
        size_t currentIndex = g_nextFileIndex.fetch_add(1);
        if (currentIndex >= (size_t)totalFiles) break; // Plus de travail

        const FileEntry& f = (*files)[currentIndex];
        uint64_t fileSize = 0;

        std::string status = VerifyFile(f, hashType, fileSize);
        
        int processedCount = g_filesProcessedCount.fetch_add(1) + 1;
        PostMessage(g_hMainWindow, WM_APP_UPDATE_GLOBAL_PROGRESS, processedCount, totalFiles);

        std::string statusPrefix;
        COLORREF statusColor;
        if (status == "OK") { statusPrefix = "[✓] "; statusColor = RGB(0, 150, 0); }
        else if (status == "CORRUPTED" || status.rfind("ERROR", 0) == 0) { statusPrefix = "[✗] "; statusColor = RGB(200, 0, 0); }
        else if (status == "MISSING") { statusPrefix = "[?] "; statusColor = RGB(255, 165, 0); }
        else if (status == "CANCELED") { break; }
        else { statusPrefix = "[!] "; statusColor = RGB(200, 0, 0); }
        
        std::string logLine = statusPrefix + f.path + " (" + FormatFileSize(fileSize) + ") - " + status;
        auto* logData = new LogData{ s2ws(logLine), statusColor };
        PostMessage(g_hMainWindow, WM_APP_APPEND_LOG, 0, (LPARAM)logData);
    }
}

/**
 * @brief Thread manager qui orchestre le processus de vérification.
 * @details Prépare les données, détermine le nombre de threads, les lance,
 * attend leur complétion, et signale la fin de la tâche.
 */
void ManagerThread() {
    // --- Initialisation ---
    g_CountOk = 0; g_CountCorrupted = 0; g_CountMissing = 0;
    g_nextFileIndex = 0; g_filesProcessedCount = 0;
    MakeCrcTable();

    auto post_log = [](const std::string& text, COLORREF color) {
        PostMessage(g_hMainWindow, WM_APP_APPEND_LOG, 0, (LPARAM)new LogData{ s2ws(text), color });
    };

    // --- Chargement du manifeste ---
    auto* files = new std::vector<FileEntry>();
    HashType hashType = HashType::NONE;
    std::vector<std::string> candidates = {"CRC.xxhash3", "CRC.crc32", "CRC.city128"};
    std::string loadedFile;

    for (const auto &c : candidates) {
        if (std::filesystem::exists(c)) {
            if (LoadManifest(c, *files, hashType)) {
                loadedFile = c;
                break;
            }
        }
    }

    if (loadedFile.empty()) {
        PostMessage(g_hMainWindow, WM_APP_TASK_ERROR, 0, (LPARAM)new LogData{L"Erreur: no (.crc32, .xxhash3, .city128) ", RGB(200,0,0)});
        delete files;
        return;
    }
    
    post_log("Manifeste chargé : " + loadedFile, RGB(0,0,0));
    int totalFiles = files->size();

    if (totalFiles == 0) {
        PostMessage(g_hMainWindow, WM_APP_TASK_ERROR, 0, (LPARAM)new LogData{L"Erreur: manifeste emptie.", RGB(200,0,0)});
        delete files;
        return;
    }

    // --- Lancement du pool de threads ---
    PostMessage(g_hMainWindow, WM_APP_UPDATE_GLOBAL_PROGRESS, 0, totalFiles);
    auto startTime = std::chrono::steady_clock::now();

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 2; // Valeur par défaut
    
    std::vector<std::thread> threads;
    for (unsigned int i = 0; i < num_threads; ++i) {
        threads.emplace_back(HashWorker, files, hashType, totalFiles);
    }

    // --- Attente de la complétion ---
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    
    delete files; // Libération de la mémoire partagée

    // --- Finalisation ---
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
    
    auto* completionData = new TaskCompleteData{ totalFiles, duration, !g_IsRunning };
    PostMessage(g_hMainWindow, WM_APP_TASK_COMPLETE, 0, (LPARAM)completionData);
}


// =================================================================================
// Section: Interface Utilisateur (Thread UI)
// =================================================================================

/**
 * @brief Ajoute une ligne de texte colorée au contrôle Rich Edit.
 * @details Doit être appelée exclusivement depuis le thread UI.
 */
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

/**
 * @brief Procédure de fenêtre principale, gère les messages Windows.
 */
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_APP_UPDATE_FILE_PROGRESS: {
            FileProgressData* data = reinterpret_cast<FileProgressData*>(lParam);
            std::wostringstream woss;
            woss << L"Files: " << data->filename << L" - " << data->percentage << L"%";
            if (data->speed_MBps > 0.0) {
                woss << L" (" << std::fixed << std::setprecision(2) << data->speed_MBps << L" Mo/s)";
            }
            SetWindowTextW(g_hLabelFileProgress, woss.str().c_str());
            SendMessage(g_hProgressFile, PBM_SETPOS, data->percentage, 0);
            delete data;
            break;
        }

        case WM_APP_UPDATE_GLOBAL_PROGRESS: {
            int current = (int)wParam;
            int total = (int)lParam;
            std::wostringstream woss;
            woss << L"Progress: " << current << L"/" << total << L" (" << ((total > 0) ? (current * 100 / total) : 0) << L"%)";
            SetWindowTextW(g_hLabelGlobalProgress, woss.str().c_str());
            SendMessage(g_hProgressGlobal, PBM_SETRANGE32, 0, total);
            SendMessage(g_hProgressGlobal, PBM_SETPOS, current, 0);
            break;
        }

        case WM_APP_APPEND_LOG: {
            LogData* data = reinterpret_cast<LogData*>(lParam);
            AppendLog_UI(data->text, data->color);
            delete data;
            break;
        }
        
        case WM_APP_TASK_ERROR: {
            LogData* data = reinterpret_cast<LogData*>(lParam);
            AppendLog_UI(data->text, data->color);
            delete data;
            g_IsRunning = false;
            SetWindowTextW(g_hBtnStart, L"Strat");
            break;
        }
        
        case WM_APP_TASK_COMPLETE: {
            TaskCompleteData* data = reinterpret_cast<TaskCompleteData*>(lParam);
            SetWindowTextW(g_hLabelFileProgress, L"Files: Prêt");
            SendMessage(g_hProgressFile, PBM_SETPOS, 0, 0);
            
            if (!data->wasCanceled) {
                AppendLog_UI(L"", RGB(0,0,0)); // Ligne vide
                std::wostringstream report;
                report << L"---FINAL ---\n"
                       << L"files: " << data->totalFiles << L"\n";
                AppendLog_UI(report.str(), RGB(0,0,0));

                auto add_report_line = [&](const std::wstring& label, int count, COLORREF color) {
                    double p = (data->totalFiles > 0) ? (static_cast<double>(count) / data->totalFiles * 100.0) : 0.0;
                    std::wostringstream line;
                    line << label << count << L" Files (" << std::fixed << std::setprecision(2) << p << L"%)";
                    AppendLog_UI(line.str(), color);
                };
                
                add_report_line(L"OK (green): ", g_CountOk, RGB(0,150,0));
                add_report_line(L"corrupted (red): ", g_CountCorrupted, RGB(200,0,0));
                add_report_line(L"Missing  (Orange): ", g_CountMissing, RGB(255,165,0));

                report.str(L""); report.clear();
                report << L"\n✓ proc finish (Durée: " << data->duration_s << L" secondes)";
                AppendLog_UI(report.str(), RGB(0, 150, 0));
                
            } else {
                AppendLog_UI(L"\n! stop by user.", RGB(200, 0, 0));
            }
            
            g_IsRunning = false;
            SetWindowTextW(g_hBtnStart, L"Start");
            delete data;
            break;
        }

        case WM_COMMAND:
            if (LOWORD(wParam) == 1) { // Bouton Démarrer/Arrêter
                if (!g_IsRunning) {
                    SendMessage(g_hLogBox, WM_SETTEXT, 0, (LPARAM)L"");
                    g_IsRunning = true;
                    std::thread(ManagerThread).detach();
                    SetWindowTextW(g_hBtnStart, L"Arrêter");
                } else {
                    g_IsRunning = false; // Les threads s'arrêteront au prochain check
                }
            } else if (LOWORD(wParam) == 2 && !g_IsRunning) { // Bouton Quitter
                DestroyWindow(hwnd);
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


// =================================================================================
// Section: Point d'Entrée de l'Application
// =================================================================================

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow) {
    // --- Initialisation des bibliothèques et contrôles ---
    LoadLibrary(TEXT("Msftedit.dll"));
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    // --- Enregistrement de la classe de fenêtre ---
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"FileHasherWindowClass";
    RegisterClassW(&wc);

    // --- Création de la fenêtre principale ---
    g_hMainWindow = CreateWindowExW(0, L"FileHasherWindowClass", L"NewCrc 0.4",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 540, nullptr, nullptr, hInst, nullptr);

    if (!g_hMainWindow) return 1;

    // --- Création des contrôles de l'interface ---
    g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 10, 10, 660, 325, g_hMainWindow, nullptr, hInst, nullptr);
    g_hLabelFileProgress = CreateWindowExW(0, L"STATIC", L"Wait", WS_CHILD | WS_VISIBLE, 10, 345, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hProgressFile = CreateWindowExW(0, PROGRESS_CLASS, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 370, 450, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hLabelGlobalProgress = CreateWindowExW(0, L"STATIC", L"Progress: 0/0 (0%)", WS_CHILD | WS_VISIBLE, 10, 400, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hProgressGlobal = CreateWindowExW(0, PROGRESS_CLASS, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 425, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hBtnStart = CreateWindowExW(0, L"BUTTON", L"Start", WS_CHILD | WS_VISIBLE, 480, 368, 90, 25, g_hMainWindow, (HMENU)1, hInst, nullptr);
    g_hBtnExit = CreateWindowExW(0, L"BUTTON", L"Exit", WS_CHILD | WS_VISIBLE, 580, 368, 90, 25, g_hMainWindow, (HMENU)2, hInst, nullptr);

    // --- Démarrage automatique (optionnel) ---
    int nArgs;
    LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist && nArgs > 1 && (lstrcmpiW(szArglist[1], L"-v") == 0)) {
        PostMessage(g_hMainWindow, WM_COMMAND, 1, 0); // Simule un clic sur "Démarrer"
    }
    LocalFree(szArglist);

    // --- Affichage de la fenêtre et boucle de messages ---
    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow); // Corrigé: Un seul argument

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return static_cast<int>(msg.wParam);
}