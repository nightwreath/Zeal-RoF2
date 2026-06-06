#define _CRT_SECURE_NO_WARNINGS

#include "hide_self_name.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>

#include "hook_wrapper.h"  // standalone `hook` class (detour) -- no ZealService needed

// Ship the diagnostic with v1 (feedback_diagnostics_from_v1.md). When 1,
// install() writes .\hsn_diag.txt (next to eqclient.ini) with base + ASLR delta
// + signature match + the seeded flag, so a wrong address / non-install / wrong
// build surfaces in a single launch. Flip to 0 once verified stable in-game.
#define HIDE_SELF_NAME_DIAGNOSE 1

namespace hide_self_name {

namespace {

// ---- SetNameSpriteState (name-sprite show/hide decision), Ghidra-derived vs
//   OUR eqgame.exe (S62, FUN_0058e2d0). __thiscall: entity in ECX, int `show`
//   on the stack (callee-cleans, RET 4). show==0 => the client's hide path
//   (clears the sprite). We model the __thiscall as __fastcall with a dummy
//   edx. Prologue:
//     B8 A8 26 00 00   MOV EAX, 0x26A8   (alloca-probe size)
//     E8 ?? ?? ?? ??   CALL __alloca_probe   (displacement is ASLR-relocated)
//     55 8B E9         PUSH EBP; MOV EBP, ECX
//   The CALL's 4 displacement bytes are wildcarded in the signature gate. ----
constexpr uintptr_t kSnsGhidra = 0x0058e2d0;
constexpr unsigned char kSnsSig[13] = {0xB8, 0xA8, 0x26, 0x00, 0x00, 0xE8, 0, 0, 0, 0, 0x55, 0x8B, 0xE9};
constexpr unsigned char kSnsMask[13] = {1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1};
using sns_fn = int(__fastcall *)(void *entity, int edx, int show);

// ---- Local-player globals, Ghidra-derived vs OUR eqgame.exe (S62). These hold
//   the Entity* the player's input controls (procMouse FUN_00516d40 turns them
//   as "you"). 0x00dd2630 = your character (Self; also InterpretCmd's in-game
//   null-gate); 0x00dd2644 = controlled / camera-view spawn. Both are 0 until
//   you zone in. Static addresses; add the ASLR delta. ----
constexpr uintptr_t kSelfGlobal = 0x00dd2630;
constexpr uintptr_t kControlledGlobal = 0x00dd2644;

constexpr char kZealIni[] = ".\\zeal.ini";
constexpr char kIniSection[] = "Zeal";
constexpr char kIniKey[] = "NameplateHideSelf";

uintptr_t g_aslr_delta = 0;
hook *g_hook = nullptr;
bool g_hidden = false;

#if HIDE_SELF_NAME_DIAGNOSE
void diag(const char *fmt, ...) {
  FILE *f = nullptr;
  fopen_s(&f, ".\\hsn_diag.txt", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(f, fmt, ap);
  va_end(ap);
  std::fclose(f);
}
#endif

// Reads *(Entity**)(ghidra_addr + delta), guarded. Returns nullptr if the
// global isn't populated yet (pre-zone-in) or unreadable.
void *read_entity_global(uintptr_t ghidra_addr) {
  const uintptr_t runtime = ghidra_addr + g_aslr_delta;
  if (IsBadReadPtr(reinterpret_cast<const void *>(runtime), sizeof(void *))) return nullptr;
  return *reinterpret_cast<void **>(runtime);
}

bool is_self(const void *entity) {
  if (!entity) return false;
  return entity == read_entity_global(kSelfGlobal) || entity == read_entity_global(kControlledGlobal);
}

int __fastcall sns_detour(void *entity, int edx, int show) {
  if (g_hidden && is_self(entity)) show = 0;  // force-hide our own name sprite
  return g_hook->original(static_cast<sns_fn>(nullptr))(entity, edx, show);
}

}  // namespace

bool is_hidden() { return g_hidden; }

void set_hidden(bool hidden) {
  g_hidden = hidden;
  WritePrivateProfileStringA(kIniSection, kIniKey, hidden ? "1" : "0", kZealIni);

  // Force an immediate self refresh so the change is visible without a relog.
  // Call the ORIGINAL (bypassing our detour) with show=0 to hide now, or show=1
  // to restore. Safe if we're not yet in-game (self is null -> skip).
  if (g_hook) {
    void *self = read_entity_global(kSelfGlobal);
    if (!self) self = read_entity_global(kControlledGlobal);
    if (self) g_hook->original(static_cast<sns_fn>(nullptr))(self, 0, hidden ? 0 : 1);
  }
}

bool install(std::uintptr_t aslr_delta) {
  g_aslr_delta = aslr_delta;
  const uintptr_t runtime = kSnsGhidra + aslr_delta;

  bool sig_ok = !IsBadReadPtr(reinterpret_cast<const void *>(runtime), sizeof(kSnsSig));
  if (sig_ok) {
    const unsigned char *p = reinterpret_cast<const unsigned char *>(runtime);
    for (size_t i = 0; i < sizeof(kSnsSig); ++i) {
      if (kSnsMask[i] && p[i] != kSnsSig[i]) {
        sig_ok = false;
        break;
      }
    }
  }

  g_hidden = GetPrivateProfileIntA(kIniSection, kIniKey, 0, kZealIni) != 0;

#if HIDE_SELF_NAME_DIAGNOSE
  {
    FILE *f = nullptr;  // truncate fresh each load
    fopen_s(&f, ".\\hsn_diag.txt", "w");
    if (f) std::fclose(f);
  }
  const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
  diag("hide_self_name install diagnostic (S62)\n");
  diag("base=0x%08X delta=0x%08X\n", static_cast<unsigned>(base), static_cast<unsigned>(aslr_delta));
  diag("SetNameSpriteState ghidra=0x%08X runtime=0x%08X sig_ok=%d\n", static_cast<unsigned>(kSnsGhidra),
       static_cast<unsigned>(runtime), sig_ok ? 1 : 0);
  diag("self_global runtime=0x%08X controlled_global runtime=0x%08X\n",
       static_cast<unsigned>(kSelfGlobal + aslr_delta), static_cast<unsigned>(kControlledGlobal + aslr_delta));
  diag("seeded g_hidden=%d (zeal.ini [Zeal] NameplateHideSelf)\n", g_hidden ? 1 : 0);
#endif

  if (!sig_ok) return false;  // wrong address for this binary -> silent no-op

  g_hook = new hook(runtime, &sns_detour, hook_type_detour);

#if HIDE_SELF_NAME_DIAGNOSE
  diag("SetNameSpriteState detour INSTALLED.\n");
#endif
  return true;
}

}  // namespace hide_self_name
