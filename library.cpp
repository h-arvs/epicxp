#include <iostream>
#include <Windows.h>
#include <MinHook.h>
#include <libhat/Scanner.hpp>
#include <cassert>

uintptr_t FindSig(std::string_view pattern) {
    auto sig = hat::parse_signature(pattern);
    assert(sig.has_value());
    auto result = hat::find_pattern(sig.value(), ".text");
    assert(result.has_result());
    return result.has_result() ? reinterpret_cast<uintptr_t>(result.get()) : 0;
}

template <typename T>
T resolveOffset(std::string_view pattern, uintptr_t offset) {
    auto match = FindSig(pattern);
    match += offset;
    return *reinterpret_cast<T*>(match);
}

struct Player {
    void addLevels(int levels) {
        static auto offset = resolveOffset<DWORD>("48 8B 80 ? ? ? ? FF 15 ? ? ? ? 49 8B 04 24 8B 97", 3);
        using func_t = void(__fastcall*)(void*, int);
        auto a = *reinterpret_cast<uintptr_t*>(this) + offset;
        return (*reinterpret_cast<func_t *>(a))(this, levels);
    }
};

struct ClientInstance {
    Player* getClientPlayer() {
        static auto offset = resolveOffset<DWORD>("48 8B 80 ? ? ? ? FF 15 ? ? ? ? 48 8B F8 48 85 C0 0F 84 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B F0 48 85 C0 0F 84", 3);
        using func_t = Player*(__fastcall*)(void*);
        auto a = *reinterpret_cast<uintptr_t *>(this) + offset;
        return (*reinterpret_cast<func_t*>(a))(this);
    }
};

bool uninject = false;
void (__fastcall* CIUpdateO)(void* ci);
void CIUpdate(ClientInstance* ci){
    static bool once = false;
    if (!once) {
        auto goop = ci->getClientPlayer();
        if (goop) {
            goop->addLevels(1000);
        }
        uninject = true;
        once = true;
    }

    return CIUpdateO(ci);
}

void init(LPVOID hInstance) {
    MH_Initialize();

    auto update = FindSig("48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 44 0F B6 FA");


    MH_CreateHook(reinterpret_cast<LPVOID*>(update), &CIUpdate, (LPVOID*)&CIUpdateO);
    MH_EnableHook(reinterpret_cast<LPVOID*>(update));

    while (!uninject) {
        Sleep(1);
    }

    MH_Uninitialize();
    FreeLibraryAndExitThread(static_cast<HMODULE>(hInstance), 0);

}

bool WINAPI DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpRes) {

    switch (fdwReason) {

        case DLL_PROCESS_ATTACH:
            CreateThread(0, 0, (LPTHREAD_START_ROUTINE)init, hInstance, 0, 0);
            break;
    };

    return TRUE;

};