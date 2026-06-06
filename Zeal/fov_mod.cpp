#define _CRT_SECURE_NO_WARNINGS

#include "fov_mod.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "hook_wrapper.h"  // standalone `hook` class (detour) -- no ZealService needed

// Ship the diagnostic with v1 (feedback_diagnostics_from_v1.md). When 1,
// install()/ensure_hook() + the first detour call write .\fov_diag.txt (module
// base, frustum-fn address, signature match, and the observed default FOV) so a
// not-yet-loaded DLL / wrong build surfaces in one launch.
#define FOV_MOD_DIAGNOSE 1

namespace fov_mod {

namespace {

// EQGraphicsDX9.dll frustum/perspective builder. RVA 0x6470 (image base
// 0x10000000). __fastcall(int frustum): ECX = frustum; [frustum+4] = FOV in
// degrees (FLD [ESI+4]; FMUL deg2rad/2; -> D3DXMatrixPerspectiveRH). The
// prologue is all register/immediate ops (no relocations) -> a stable guard.
constexpr char kGfxDll[] = "EQGraphicsDX9.dll";
constexpr unsigned kFrustumRva = 0x6470;
constexpr int kFovFieldOff = 4;
constexpr unsigned char kSig[15] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0, 0x81, 0xEC,
                                    0x48, 0x02, 0x00, 0x00, 0x56, 0x8B, 0xF1};
using frustum_fn = void(__fastcall *)(int frustum);

constexpr char kZealIni[] = ".\\zeal.ini";
constexpr char kSection[] = "Zeal";
constexpr char kKeyFov[] = "Fov";

constexpr float kMinFov = 45.0f;
constexpr float kMaxFov = 90.0f;
constexpr float kDefaultFov = 45.0f;
// Only override frustums whose stored FOV looks like a world perspective (deg),
// so we don't disturb any non-world frustum that reuses this fn.
constexpr float kOverrideLo = 20.0f;
constexpr float kOverrideHi = 120.0f;

// In-game gate: don't widen the character-select 3D preview (its Self entity is
// non-null, so an entity check is useless). Gate on game->game_state instead:
// game object global = 0x00e67ccc (assigned by the ctor FUN_005338a0);
// game_state at +0x5c8 (Ghidra-verified: compared ==5 INGAME / ==1 CHARSELECT).
constexpr uintptr_t kGameGlobal = 0x00e67ccc;
constexpr uintptr_t kGameStateOff = 0x5c8;
constexpr int kGameStateInGame = 5;  // GAMESTATE_INGAME
constexpr uintptr_t kEqgamePreferredBase = 0x00400000;
uintptr_t g_eqgame_delta = 0;

hook *g_hook = nullptr;
float g_fov = kDefaultFov;
bool g_enabled = false;

#if FOV_MOD_DIAGNOSE
bool g_logged_first = false;
void diag(const char *fmt, ...) {
  FILE *f = nullptr;
  fopen_s(&f, ".\\fov_diag.txt", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(f, fmt, ap);
  va_end(ap);
  std::fclose(f);
}
#endif

bool in_game() {
  void **pgame = reinterpret_cast<void **>(kGameGlobal + g_eqgame_delta);
  if (IsBadReadPtr(pgame, sizeof(void *))) return false;
  void *game = *pgame;
  if (!game) return false;
  int *pstate = reinterpret_cast<int *>(reinterpret_cast<char *>(game) + kGameStateOff);
  if (IsBadReadPtr(pstate, sizeof(int))) return false;
  return *pstate == kGameStateInGame;  // not char-select / loading
}

void __fastcall frustum_detour(int frustum) {
  if (g_enabled && frustum) {
    float *pfov = reinterpret_cast<float *>(frustum + kFovFieldOff);
    if (!IsBadReadPtr(pfov, sizeof(float))) {
      const float orig = *pfov;
#if FOV_MOD_DIAGNOSE
      if (!g_logged_first) {
        g_logged_first = true;
        diag("first frustum call: FOV=%g in_game=%d (g_fov=%g)\n", orig, in_game() ? 1 : 0, g_fov);
      }
#endif
      // Override ONLY for the projection build, then restore -- [frustum+4] is
      // also read by the camera/zoom system, so a persistent change zooms the
      // camera. In-game only (skip char-select preview) + plausible world FOV.
      if (in_game() && orig >= kOverrideLo && orig <= kOverrideHi) {
        *pfov = g_fov;
        g_hook->original(static_cast<frustum_fn>(nullptr))(frustum);
        *pfov = orig;
        return;
      }
    }
  }
  g_hook->original(static_cast<frustum_fn>(nullptr))(frustum);
}

bool ensure_hook() {
  if (g_hook) return true;
  HMODULE gfx = GetModuleHandleA(kGfxDll);
  const uintptr_t fn = gfx ? (reinterpret_cast<uintptr_t>(gfx) + kFrustumRva) : 0;
  bool sig_ok = fn && !IsBadReadPtr(reinterpret_cast<void *>(fn), sizeof(kSig)) &&
                std::memcmp(reinterpret_cast<void *>(fn), kSig, sizeof(kSig)) == 0;
#if FOV_MOD_DIAGNOSE
  diag("ensure_hook: gfx=0x%08X frustum_fn=0x%08X sig_ok=%d\n", reinterpret_cast<unsigned>(gfx),
       static_cast<unsigned>(fn), sig_ok ? 1 : 0);
#endif
  if (!sig_ok) return false;
  g_hook = new hook(static_cast<int>(fn), &frustum_detour, hook_type_detour);
#if FOV_MOD_DIAGNOSE
  diag("frustum detour INSTALLED at 0x%08X\n", static_cast<unsigned>(fn));
#endif
  return true;
}

}  // namespace

float get_fov() { return g_fov; }
bool is_enabled() { return g_enabled; }

bool set_fov(float fov) {
  if (fov < kMinFov || fov > kMaxFov) return false;
  g_fov = fov;
  g_enabled = true;
  char v[32];
  _snprintf_s(v, sizeof(v), _TRUNCATE, "%g", fov);
  WritePrivateProfileStringA(kSection, kKeyFov, v, kZealIni);
  return ensure_hook();
}

void disable() {
  g_enabled = false;
  WritePrivateProfileStringA(kSection, kKeyFov, "0", kZealIni);
}

bool install() {
#if FOV_MOD_DIAGNOSE
  {
    FILE *f = nullptr;  // truncate fresh each load
    fopen_s(&f, ".\\fov_diag.txt", "w");
    if (f) std::fclose(f);
  }
  diag("fov_mod install diagnostic (S62, DX9 frustum hook)\n");
#endif
  g_eqgame_delta = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL)) - kEqgamePreferredBase;
  char buf[32] = {0};
  GetPrivateProfileStringA(kSection, kKeyFov, "0", buf, sizeof(buf), kZealIni);
  const float f = static_cast<float>(std::atof(buf));
  if (f >= kMinFov && f <= kMaxFov) {
    g_fov = f;
    g_enabled = true;
  }
#if FOV_MOD_DIAGNOSE
  diag("seeded Fov=%g enabled=%d\n", g_fov, g_enabled ? 1 : 0);
#endif
  return ensure_hook();  // installs now if the gfx DLL is loaded; else first /fov does it
}

}  // namespace fov_mod
