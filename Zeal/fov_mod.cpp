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

// EQGraphicsDX9.dll dPVS occlusion-cull frustum builder, RVA 0xed20.
// __fastcall(scene). It reads the CULL camera's FOV (a different camera object
// from the projection's), fptan's it, and calls DPVS::Camera::setFrustum -- so
// widening only the projection left the cull at 45 (distant geometry culled when
// panning). We bracket [cullcam+4] during this fn too. Ghidra-verified deref:
//   B       = *(gfxbase + 0x179108)       (DAT_10179108 content)
//   cullcam = *(B + 0x34)                  (B[0xd])
//   FOV     = *(float*)(cullcam + 4)       (vtable getter returns [cullcam+4])
// Prologue is all reg/imm ops up to the SEH-handler push -> 14-byte stable guard.
constexpr unsigned kCullRva = 0xed20;
constexpr unsigned kEngineGlobalRva = 0x179108;
constexpr int kCullCamPtrOff = 0x34;
constexpr unsigned char kCullSig[14] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0, 0x64,
                                        0xA1, 0x00, 0x00, 0x00, 0x00, 0x6A, 0xFF};
using cull_fn = void(__fastcall *)(void *scene);

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

hook *g_hook = nullptr;       // projection (FUN_10006470)
hook *g_cull_hook = nullptr;  // dPVS cull frustum (FUN_1000ed20)
uintptr_t g_gfx_base = 0;     // EQGraphicsDX9.dll runtime base
float g_fov = kDefaultFov;
bool g_enabled = false;

#if FOV_MOD_DIAGNOSE
bool g_logged_first = false;
bool g_logged_cull = false;
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

// Resolves the dPVS cull camera's FOV field: *( *(gfxbase+0x179108) + 0x34 ) + 4.
// Guarded at each dereference. Returns nullptr if not resolvable yet.
float *cull_fov_field() {
  if (!g_gfx_base) return nullptr;
  void **pB = reinterpret_cast<void **>(g_gfx_base + kEngineGlobalRva);
  if (IsBadReadPtr(pB, sizeof(void *)) || !*pB) return nullptr;
  void **pcam = reinterpret_cast<void **>(reinterpret_cast<char *>(*pB) + kCullCamPtrOff);
  if (IsBadReadPtr(pcam, sizeof(void *)) || !*pcam) return nullptr;
  float *pfov = reinterpret_cast<float *>(reinterpret_cast<char *>(*pcam) + kFovFieldOff);
  return IsBadReadPtr(pfov, sizeof(float)) ? nullptr : pfov;
}

void __fastcall cull_detour(void *scene) {
  if (g_enabled && in_game()) {
    float *pfov = cull_fov_field();
    if (pfov) {
      const float orig = *pfov;
#if FOV_MOD_DIAGNOSE
      if (!g_logged_cull) {
        g_logged_cull = true;
        diag("first cull call: cull FOV=%g (g_fov=%g)\n", orig, g_fov);
      }
#endif
      // dPVS rebuilds its frustum when the FOV changes, so it picks up g_fov.
      // Restore after so the camera/zoom (which reads this field elsewhere) and
      // /fov off are unaffected.
      if (orig >= kOverrideLo && orig <= kOverrideHi) {
        *pfov = g_fov;
        g_cull_hook->original(static_cast<cull_fn>(nullptr))(scene);
        *pfov = orig;
        return;
      }
    }
  }
  g_cull_hook->original(static_cast<cull_fn>(nullptr))(scene);
}

bool ensure_hook() {
  if (g_hook && g_cull_hook) return true;
  HMODULE gfx = GetModuleHandleA(kGfxDll);
  if (!gfx) {
#if FOV_MOD_DIAGNOSE
    diag("ensure_hook: %s not loaded yet\n", kGfxDll);
#endif
    return false;
  }
  g_gfx_base = reinterpret_cast<uintptr_t>(gfx);

  if (!g_hook) {
    const uintptr_t fn = g_gfx_base + kFrustumRva;
    const bool sig_ok = !IsBadReadPtr(reinterpret_cast<void *>(fn), sizeof(kSig)) &&
                        std::memcmp(reinterpret_cast<void *>(fn), kSig, sizeof(kSig)) == 0;
#if FOV_MOD_DIAGNOSE
    diag("ensure_hook: frustum_fn=0x%08X sig_ok=%d\n", static_cast<unsigned>(fn), sig_ok ? 1 : 0);
#endif
    if (sig_ok) {
      g_hook = new hook(static_cast<int>(fn), &frustum_detour, hook_type_detour);
#if FOV_MOD_DIAGNOSE
      diag("frustum (projection) detour INSTALLED at 0x%08X\n", static_cast<unsigned>(fn));
#endif
    }
  }
  if (!g_cull_hook) {
    const uintptr_t cfn = g_gfx_base + kCullRva;
    const bool csig_ok = !IsBadReadPtr(reinterpret_cast<void *>(cfn), sizeof(kCullSig)) &&
                         std::memcmp(reinterpret_cast<void *>(cfn), kCullSig, sizeof(kCullSig)) == 0;
#if FOV_MOD_DIAGNOSE
    diag("ensure_hook: cull_fn=0x%08X sig_ok=%d\n", static_cast<unsigned>(cfn), csig_ok ? 1 : 0);
#endif
    if (csig_ok) {
      g_cull_hook = new hook(static_cast<int>(cfn), &cull_detour, hook_type_detour);
#if FOV_MOD_DIAGNOSE
      diag("dPVS cull detour INSTALLED at 0x%08X\n", static_cast<unsigned>(cfn));
#endif
    }
  }
  return g_hook != nullptr;  // projection is the essential hook; cull is the fix-up
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
