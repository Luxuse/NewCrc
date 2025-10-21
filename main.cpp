/**
 * @file main.cpp
 * @brief Application Win32 multithread pour la vérification de l'intégrité de fichiers par hachage.
 * @version 0.6 (Modern C++20/23)
 *
 * @details
 * Ce programme vérifie une liste de fichiers par rapport à leurs sommes de contrôle
 * (CRC32, XXH3, CityHash128) spécifiées dans un fichier manifeste.
 * L'architecture utilise un pool de std::jthread (C++20) pour paralléliser les calculs
 * de hachage, un std::stop_token pour une annulation propre, et une communication
 * asynchrone par PostMessage (avec std::unique_ptr pour la sécurité de la mémoire)
 * pour mettre à jour l'interface utilisateur sans la bloquer.
 */

// --- Inclusions Standards et Externes ---
#include <windows.h>
#include <commctrl.h>   // Pour les contrôles communs (barres de progression)
#include <richedit.h>   // Pour le contrôle Rich Edit (log coloré)
#include <string>
#include <vector>
#include <fstream>
#include <sstream>      // Gardé pour l'analyse de ligne (iss)
#include <thread>       // Pour std::jthread
#include <atomic>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <chrono>
#include <deque>
#include <memory>       // Pour std::unique_ptr
#include <format>       // Pour std::format (C++20)
#include <string_view>  // Pour std::string_view (C++17)
#include <mutex>        // Pour std::call_once

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
#define WM_APP_UPDATE_FILE_PROGRESS   (WM_APP + 1)
#define WM_APP_UPDATE_GLOBAL_PROGRESS (WM_APP + 2)
#define WM_APP_APPEND_LOG             (WM_APP + 3)
#define WM_APP_TASK_COMPLETE          (WM_APP + 4)
#define WM_APP_TASK_ERROR             (WM_APP + 5)

/**
 * @struct FileProgressData
 * @brief Transporte les données de progression. Géré par std::unique_ptr.
 */
struct FileProgressData {
    std::wstring filename;
    int percentage;
    double speed_MBps;
};

/**
 * @struct LogData
 * @brief Transporte les données de log. Géré par std::unique_ptr.
 */
struct LogData {
    std::wstring text;
    COLORREF color;
};

/**
 * @struct TaskCompleteData
 * @brief Transporte les statistiques finales. Géré par std::unique_ptr.
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

/**
 * @enum VerifyStatus
 * @brief Statut de retour typé pour la vérification de fichier.
 */
enum class VerifyStatus {
    OK,
    CORRUPTED,
    MISSING,
    ERROR_SIZE,
    ERROR_OPEN,
    CANCELED,
    ERROR_UNSUPPORTED_HASH
};


// --- Handle de fenêtres et variables d'état globales ---
HWND g_hMainWindow;
HWND g_hProgressGlobal, g_hProgressFile, g_hLogBox;
HWND g_hBtnStart, g_hBtnExit;
HWND g_hLabelGlobalProgress, g_hLabelFileProgress;

/// @brief Gère la demande d'arrêt pour tous les threads de travail (C++20).
std::stop_source g_stopSource;
/// @brief Gère le thread manager principal (C++20).
std::jthread g_managerThread;

// --- Compteurs atomiques pour les statistiques ---
std::atomic<int> g_CountOk(0);
std::atomic<int> g_CountCorrupted(0);
std::atomic<int> g_CountMissing(0);

// --- Synchronisation du pool de threads ---
std::atomic<size_t> g_nextFileIndex(0);
std::atomic<int> g_filesProcessedCount(0);


// =================================================================================
// Section: Fonctions Utilitaires
// =================================================================================

/**
 * @brief Calcule la vitesse de traitement en Mo/s sur une fenêtre glissante.
 * (Inchangé, déjà moderne)
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
 * @brief Convertit une chaîne UTF-8 (std::string_view) en UTF-16 (std::wstring).
 * Utilise std::string_view (C++17).
 */
std::wstring s2ws(std::string_view s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.length()), nullptr, 0);
    if (len == 0) return L"";
    std::wstring r(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.length()), &r[0], len);
    return r;
}

/**
 * @brief Extrait le nom de fichier d'un chemin complet.
 * Utilise std::filesystem (C++17).
 */
std::string GetFileName(std::string_view path) {
    return std::filesystem::path(path).filename().string();
}

/**
 * @brief Formate une taille en octets en une chaîne lisible (Ko, Mo, Go).
 * Utilise std::format (C++20).
 */
std::string FormatFileSize(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int i = 0;
    double size = static_cast<double>(bytes);
    while (size >= 1024 && i < 3) {
        size /= 1024;
        i++;
    }
    return std::format("{:.2f} {}", size, units[i]);
}

/**
 * @brief Normalise une chaîne de hash (minuscules, sans "0x" ni zéros en tête).
 * Utilise std::string_view (C++17).
 */
std::string NormalizeHash(std::string_view h) {
    std::string s(h); // Crée une copie pour la modification
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    if (s.starts_with("0x")) s = s.substr(2);
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
// Garantit que MakeCrcTable() n'est appelée qu'une seule fois.
static std::once_flag g_crcTableFlag;


// =================================================================================
// Section: Logique de Traitement des Fichiers (Threads Workers)
// =================================================================================

/**
 * @brief Vérifie un fichier unique en calculant son hash et en le comparant.
 * @details Gère l'annulation via std::stop_token (C++20).
 * Utilise std::unique_ptr pour les messages de progression.
 * Utilise std::format (C++20) pour la sortie de hash.
 * Retourne un VerifyStatus typé.
 * @param stopToken Le token pour vérifier si l'arrêt a été demandé.
 * @param item L'entrée de fichier à vérifier.
 * @param hashType L'algorithme de hash à utiliser.
 * @param[out] fileSize Taille du fichier en octets.
 * @return Un VerifyStatus indiquant le résultat.
 */
VerifyStatus VerifyFile(std::stop_token stopToken, const FileEntry &item, HashType hashType, uint64_t &fileSize) {
    namespace fs = std::filesystem;
    std::string filename = GetFileName(item.path);

    // Lambda pour poster la progression en utilisant std::unique_ptr
    auto post_progress = [&](int percentage, double speed) {
        auto data = std::make_unique<FileProgressData>(s2ws(filename), percentage, speed);
        PostMessage(g_hMainWindow, WM_APP_UPDATE_FILE_PROGRESS, 0, (LPARAM)data.release());
    };

    post_progress(0, 0.0);

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

    const size_t BUF_SIZE = 16 * 1024 * 1024; // 16 Mo
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
                if (stopToken.stop_requested()) return VerifyStatus::CANCELED;
            }
            crc ^= 0xFFFFFFFFu;
            resultHash = std::format("{:08x}", crc); // C++20
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
                if (stopToken.stop_requested()) {
                    XXH3_freeState(state);
                    return VerifyStatus::CANCELED;
                }
            }
            uint64_t h = XXH3_64bits_digest(state);
            XXH3_freeState(state);
            resultHash = std::format("{:016x}", h); // C++20
            break;
        }
        case HashType::CITY128: {
            // Note: CityHash128 sans API streaming (comme dans l'original)
            std::vector<char> fileContent;
            fileContent.reserve(fileSize);
            while (f) {
                f.read(buffer.data(), BUF_SIZE);
                std::streamsize r = f.gcount();
                if (r == 0) break;
                fileContent.insert(fileContent.end(), buffer.data(), buffer.data() + r);
                update_logic(r);
                if (stopToken.stop_requested()) return VerifyStatus::CANCELED;
            }
            uint128 hash128 = CityHash128(fileContent.data(), fileContent.size());
            resultHash = std::format("{:016x}{:016x}", // C++20
                                     Uint128High64(hash128),
                                     Uint128Low64(hash128));
            break;
        }
        default: return VerifyStatus::ERROR_UNSUPPORTED_HASH;
    }

    VerifyStatus status = (NormalizeHash(resultHash) == NormalizeHash(item.expectedHash)) 
                          ? VerifyStatus::OK 
                          : VerifyStatus::CORRUPTED;
    
    if (status == VerifyStatus::OK) g_CountOk++;
    else g_CountCorrupted++;
    
    post_progress(100, speedBuffer.GetSpeed());
    return status;
}

/**
 * @brief Parse un fichier manifeste de sommes de contrôle.
 * Utilise std::filesystem::path (C++17).
 */
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
        if (line.empty() || line.starts_with(';')) continue; // C++20 starts_with
        std::istringstream iss(line);
        std::string hash, path;
        iss >> hash;
        std::getline(iss, path);
        
        // Nettoyer le chemin
        path.erase(0, path.find_first_not_of(" *"));
        
        if (!path.empty()) outFiles.push_back({path, hash});
    }
    return true;
}


// =================================================================================
// Section: Logique de Multithreading
// =================================================================================

/**
 * @brief Fonction exécutée par chaque thread ouvrier (jthread).
 * @details Gère l'annulation via std::stop_token (C++20).
 * Utilise std::format (C++20) et std::unique_ptr pour le logging.
 * @param stopToken Token d'arrêt propagé depuis le thread manager.
 * @param files Pointeur vers le vecteur de fichiers (lecture seule).
 * @param hashType L'algorithme de hash à utiliser.
 * @param totalFiles Le nombre total de fichiers.
 */
void HashWorker(std::stop_token stopToken, const std::vector<FileEntry>* files, HashType hashType, int totalFiles) {
    
    while (!stopToken.stop_requested()) {
        size_t currentIndex = g_nextFileIndex.fetch_add(1);
        if (currentIndex >= (size_t)totalFiles) break; // Plus de travail

        const FileEntry& f = (*files)[currentIndex];
        uint64_t fileSize = 0;

        VerifyStatus status = VerifyFile(stopToken, f, hashType, fileSize);
        
        // Si l'arrêt a été demandé pendant VerifyFile, on s'arrête ici.
        if (status == VerifyStatus::CANCELED) break;
        
        int processedCount = g_filesProcessedCount.fetch_add(1) + 1;
        PostMessage(g_hMainWindow, WM_APP_UPDATE_GLOBAL_PROGRESS, processedCount, totalFiles);

        std::string statusPrefix;
        COLORREF statusColor;

        switch (status) {
            case VerifyStatus::OK:
                statusPrefix = "[✓] "; statusColor = RGB(0, 150, 0); break;
            case VerifyStatus::CORRUPTED:
            case VerifyStatus::ERROR_SIZE:
            case VerifyStatus::ERROR_OPEN:
            case VerifyStatus::ERROR_UNSUPPORTED_HASH:
                statusPrefix = "[✗] "; statusColor = RGB(200, 0, 0); break;
            case VerifyStatus::MISSING:
                statusPrefix = "[?] "; statusColor = RGB(255, 165, 0); break;
            case VerifyStatus::CANCELED: // Ne devrait pas arriver ici, mais pour être complet
                break;
        }
        
        std::string statusStr;
        if (status == VerifyStatus::OK) statusStr = "OK";
        else if (status == VerifyStatus::CORRUPTED) statusStr = "CORRUPTED";
        else if (status == VerifyStatus::MISSING) statusStr = "MISSING";
        else statusStr = "ERROR";

        std::string logLine = std::format("{} {} ({}) - {}", 
                                          statusPrefix, f.path, FormatFileSize(fileSize), statusStr);
        
        auto logData = std::make_unique<LogData>(s2ws(logLine), statusColor);
        PostMessage(g_hMainWindow, WM_APP_APPEND_LOG, 0, (LPARAM)logData.release());
    }
}

/**
 * @brief Thread manager qui orchestre le processus de vérification.
 * @details Utilise std::jthread pour le pool de workers (C++20).
 * Utilise std::call_once pour l'initialisation de la table CRC.
 * Utilise std::unique_ptr pour les données et les messages.
 * @param stopToken Token d'arrêt (C++20) pour l'annulation.
 */
void ManagerThread(std::stop_token stopToken) {
    // --- Initialisation ---
    g_CountOk = 0; g_CountCorrupted = 0; g_CountMissing = 0;
    g_nextFileIndex = 0; g_filesProcessedCount = 0;
    std::call_once(g_crcTableFlag, MakeCrcTable); // Initialisation thread-safe

    auto post_log = [](const std::string& text, COLORREF color) {
        auto data = std::make_unique<LogData>(s2ws(text), color);
        PostMessage(g_hMainWindow, WM_APP_APPEND_LOG, 0, (LPARAM)data.release());
    };

    // --- Chargement du manifeste ---
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
        auto err = std::make_unique<LogData>(L"Erreur: Aucun manifeste (.crc32, .xxhash3, .city128) trouvé.", RGB(200,0,0));
        PostMessage(g_hMainWindow, WM_APP_TASK_ERROR, 0, (LPARAM)err.release());
        return;
    }
    
    post_log("Manifeste chargé : " + loadedFile, RGB(0,0,0));
    int totalFiles = files->size();

    if (totalFiles == 0) {
        auto err = std::make_unique<LogData>(L"Erreur: Le manifeste est vide.", RGB(200,0,0));
        PostMessage(g_hMainWindow, WM_APP_TASK_ERROR, 0, (LPARAM)err.release());
        return;
    }

    // --- Lancement du pool de threads ---
    PostMessage(g_hMainWindow, WM_APP_UPDATE_GLOBAL_PROGRESS, 0, totalFiles);
    auto startTime = std::chrono::steady_clock::now();

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 2; // Valeur par défaut
    
    std::vector<std::jthread> threads;
    for (unsigned int i = 0; i < num_threads; ++i) {
        // Le stopToken du manager est passé aux workers.
        threads.emplace_back(HashWorker, stopToken, files.get(), hashType, totalFiles);
    }

    // --- Attente de la complétion ---
    // Pas besoin de boucle join() !
    // Les destructeurs de std::jthread dans ~std::vector<std::jthread> 
    // s'en chargeront automatiquement lorsque 'threads' sortira du scope.
    
    // files.reset(); // (Optionnel) unique_ptr le fera aussi en sortie de scope

    // --- Finalisation ---
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();
    
    auto completionData = std::make_unique<TaskCompleteData>(totalFiles, duration, stopToken.stop_requested());
    PostMessage(g_hMainWindow, WM_APP_TASK_COMPLETE, 0, (LPARAM)completionData.release());
}


// =================================================================================
// Section: Interface Utilisateur (Thread UI)
// =================================================================================

/**
 * @brief Ajoute une ligne de texte colorée au contrôle Rich Edit.
 * (Inchangé, API Win32 pure)
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
 * @details Utilise std::unique_ptr pour gérer la mémoire des messages (RAII).
 * Utilise std::format (C++20) pour la mise à jour des labels.
 * Gère le cycle de vie de std::jthread et std::stop_source.
 */
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_APP_UPDATE_FILE_PROGRESS: {
            // RAII: Le pointeur est géré par unique_ptr dès sa réception.
            auto data = std::unique_ptr<FileProgressData>(reinterpret_cast<FileProgressData*>(lParam));
            
            std::wstring text;
            if (data->speed_MBps > 0.0) {
                text = std::format(L"Fichier: {} - {}% ({:.2f} Mo/s)", // C++20
                                   data->filename, data->percentage, data->speed_MBps);
            } else {
                text = std::format(L"Fichier: {} - {}%", // C++20
                                   data->filename, data->percentage);
            }
            SetWindowTextW(g_hLabelFileProgress, text.c_str());
            SendMessage(g_hProgressFile, PBM_SETPOS, data->percentage, 0);
            
            // delete data; // Plus nécessaire! unique_ptr s'en charge.
            break;
        }

        case WM_APP_UPDATE_GLOBAL_PROGRESS: {
            int current = (int)wParam;
            int total = (int)lParam;
            std::wstring text = std::format(L"Progrès: {}/{} ({}%)", // C++20
                                            current, total, (total > 0) ? (current * 100 / total) : 0);
            
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
            
            if (g_managerThread.joinable()) {
                g_managerThread.join(); // Nettoyer le thread terminé
            }
            SetWindowTextW(g_hBtnStart, L"Démarrer");
            break;
        }
        
        case WM_APP_TASK_COMPLETE: {
            auto data = std::unique_ptr<TaskCompleteData>(reinterpret_cast<TaskCompleteData*>(lParam));
            
            SetWindowTextW(g_hLabelFileProgress, L"Fichier: Prêt");
            SendMessage(g_hProgressFile, PBM_SETPOS, 0, 0);
            
            if (!data->wasCanceled) {
                AppendLog_UI(L"", RGB(0,0,0)); // Ligne vide
                std::wstring report = std::format(L"--- RAPPORT FINAL ---\nFichiers totaux: {}\n", data->totalFiles);
                AppendLog_UI(report, RGB(0,0,0));

                auto add_report_line = [&](const std::wstring& label, int count, COLORREF color) {
                    double p = (data->totalFiles > 0) ? (static_cast<double>(count) / data->totalFiles * 100.0) : 0.0;
                    std::wstring line = std::format(L"{}: {} Fichiers ({:.2f}%)", label, count, p);
                    AppendLog_UI(line, color);
                };
                
                add_report_line(L"  [✓] Intègres", g_CountOk.load(), RGB(0,150,0));
                add_report_line(L"  [✗] Corrompus", g_CountCorrupted.load(), RGB(200,0,0));
                add_report_line(L"  [?] Manquants", g_CountMissing.load(), RGB(255,165,0));

                report = std::format(L"\n✓ Vérification terminée (Durée: {} secondes)", data->duration_s);
                AppendLog_UI(report, RGB(0, 150, 0));
                
            } else {
                AppendLog_UI(L"\n! Opération annulée par l'utilisateur.", RGB(200, 0, 0));
            }
            
            if (g_managerThread.joinable()) {
                g_managerThread.join(); // Nettoyer le thread terminé
            }
            SetWindowTextW(g_hBtnStart, L"Démarrer");
            break;
        }

        case WM_COMMAND:
            if (LOWORD(wParam) == 1) { // Bouton Démarrer/Arrêter
                if (!g_managerThread.joinable()) {
                    // Démarrer
                    SendMessage(g_hLogBox, WM_SETTEXT, 0, (LPARAM)L"");
                    
                    g_stopSource = std::stop_source(); // Créer une nouvelle source d'arrêt
                    g_managerThread = std::jthread(ManagerThread, g_stopSource.get_token());
                    
                    SetWindowTextW(g_hBtnStart, L"Arrêter");
                } else {
                    // Arrêter
                    g_stopSource.request_stop(); // Demander l'arrêt (C++20)
                    // L'UI sera mise à jour lorsque le message TASK_COMPLETE arrivera.
                }
            } else if (LOWORD(wParam) == 2 && !g_managerThread.joinable()) { // Bouton Quitter
                DestroyWindow(hwnd);
            }
            break;

        case WM_CLOSE:
            if (!g_managerThread.joinable()) {
                DestroyWindow(hwnd);
            } else {
                // Optionnel: Demander à l'utilisateur s'il veut vraiment quitter
                // Pour l'instant, on ignore la fermeture si le travail est en cours.
            }
            break;

        case WM_DESTROY:
            // S'assurer que le thread est arrêté et joint avant de quitter
            if (g_managerThread.joinable()) {
                g_stopSource.request_stop();
                g_managerThread.join();
            }
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
    g_hMainWindow = CreateWindowExW(0, L"FileHasherWindowClass", L"NewCrc 0.4.1",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 540, nullptr, nullptr, hInst, nullptr);

    if (!g_hMainWindow) return 1;

    // --- Création des contrôles de l'interface ---
    g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"RICHEDIT50W", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 10, 10, 660, 325, g_hMainWindow, nullptr, hInst, nullptr);
    g_hLabelFileProgress = CreateWindowExW(0, L"STATIC", L"File ready", WS_CHILD | WS_VISIBLE, 10, 345, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hProgressFile = CreateWindowExW(0, PROGRESS_CLASS, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 370, 450, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hLabelGlobalProgress = CreateWindowExW(0, L"STATIC", L"Progress: 0/0 (0%)", WS_CHILD | WS_VISIBLE, 10, 400, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hProgressGlobal = CreateWindowExW(0, PROGRESS_CLASS, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH, 10, 425, 660, 20, g_hMainWindow, nullptr, hInst, nullptr);
    g_hBtnStart = CreateWindowExW(0, L"BUTTON", L"START", WS_CHILD | WS_VISIBLE, 480, 368, 90, 25, g_hMainWindow, (HMENU)1, hInst, nullptr);
    g_hBtnExit = CreateWindowExW(0, L"BUTTON", L"QUIT", WS_CHILD | WS_VISIBLE, 580, 368, 90, 25, g_hMainWindow, (HMENU)2, hInst, nullptr);

    // --- Démarrage automatique (optionnel) ---
    int nArgs;
    LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (szArglist && nArgs > 1 && (lstrcmpiW(szArglist[1], L"-v") == 0)) {
        PostMessage(g_hMainWindow, WM_COMMAND, 1, 0); // Simule un clic sur "Démarrer"
    }
    LocalFree(szArglist);

    // --- Affichage de la fenêtre et boucle de messages ---
    ShowWindow(g_hMainWindow, nCmdShow);
    UpdateWindow(g_hMainWindow); // Corrigé (l'original avait un paramètre en trop)

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return static_cast<int>(msg.wParam);
}