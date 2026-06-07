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
#define FOV_MOD_DIAGNOSE 0

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

// EQGraphicsDX9.dll top render orchestrator, RVA 0x97420 (callers=0). It drives
// the whole frame: scene render (FUN_10017a80 x2, render cam B[0xe]) -> a second
// projection build -> dPVS cull (0xed20) -> precipitation -> overlay/name draws.
// S63 finding: the world (render cam) IS widened, but the CULL camera (B[0xd])
// FOV is read by LATE-frame consumers (cull, precipitation, and -- the leading
// suspect -- the overhead-name billboard) AFTER our per-fn brackets have restored
// it to 45 -> names project at 45 while the scene renders at g_fov. Fix: bracket
// the WHOLE orchestrator -- hold the cull cam FOV = g_fov for the entire frame,
// restore on exit. The render cam (B[0xe]) is left untouched, so the 3rd-person
// camera-distance/zoom (which reads the render cam) is unaffected.
// Prologue (same shape as InterpretCmd, whose split prologue the hook trampoline
// already handles): 6A FF | 68 <imm32 SEH-handler, ASLR-relocated> | 64 A1 00 00
// 00 00 50 64 89 25 00 00 00 00 83 EC 30 -> match 3-byte prefix + 17-byte suffix,
// skipping the relocated push immediate.
constexpr unsigned kOrchRva = 0x97420;
constexpr unsigned char kOrchSigA[3] = {0x6A, 0xFF, 0x68};
constexpr unsigned char kOrchSigB[17] = {0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0x89,
                                         0x25, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x30};
constexpr int kCullCamIdx = 0xd;    // B[0xd] = dPVS cull camera
constexpr int kRenderCamIdx = 0xe;  // B[0xe] = render camera (drives zoom; do NOT persist)
using orch_fn = void(__fastcall *)(int *param_1);

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
hook *g_orch_hook = nullptr;  // render orchestrator (FUN_10097420) -- full-frame cull-FOV bracket
uintptr_t g_gfx_base = 0;     // EQGraphicsDX9.dll runtime base
float g_fov = kDefaultFov;
bool g_enabled = false;

#if FOV_MOD_DIAGNOSE
int g_frustum_calls = 0;  // log the first few FUN_10006470 calls per launch (incl. the late piVar7 build)
bool g_logged_cull = false;
bool g_logged_orch = false;
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
      if (g_frustum_calls < 8) {
        ++g_frustum_calls;
        const bool over = in_game() && orig >= kOverrideLo && orig <= kOverrideHi;
        diag("frustum call #%d: cam=0x%08X FOV=%g in_game=%d override=%d (g_fov=%g)\n", g_frustum_calls,
             static_cast<unsigned>(frustum), orig, in_game() ? 1 : 0, over ? 1 : 0, g_fov);
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

// Resolves camera B[idx]'s FOV field: *( *(gfxbase+0x179108) + idx*4 ) + 4.
// Guarded at each dereference. Returns nullptr if not resolvable yet.
float *cam_fov_field(int idx) {
  if (!g_gfx_base) return nullptr;
  void **pB = reinterpret_cast<void **>(g_gfx_base + kEngineGlobalRva);
  if (IsBadReadPtr(pB, sizeof(void *)) || !*pB) return nullptr;
  void **pcam = reinterpret_cast<void **>(reinterpret_cast<char *>(*pB) + idx * 4);
  if (IsBadReadPtr(pcam, sizeof(void *)) || !*pcam) return nullptr;
  float *pfov = reinterpret_cast<float *>(reinterpret_cast<char *>(*pcam) + kFovFieldOff);
  return IsBadReadPtr(pfov, sizeof(float)) ? nullptr : pfov;
}
float *cull_fov_field() { return cam_fov_field(kCullCamIdx); }  // B[0xd] (kCullCamPtrOff == kCullCamIdx*4)

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

// Full-frame cull-FOV bracket (S63 fix candidate for the nameplate float). Hold
// the cull camera (B[0xd]) FOV = g_fov across the ENTIRE render so every
// late-frame consumer -- the dPVS cull, precipitation, and the suspected
// overhead-name billboard -- projects at g_fov instead of the per-fn-restored 45.
// The render cam (B[0xe]) is deliberately NOT touched here, so the 3rd-person
// camera-distance/zoom is unaffected. Subsumes the cull_detour's job; the
// cull_detour is kept as a belt-and-suspenders guard for the cull build itself.
void __fastcall orch_detour(int *param_1) {
  if (g_enabled && in_game()) {
    float *pfov = cam_fov_field(kCullCamIdx);
    if (pfov) {
      const float orig = *pfov;
#if FOV_MOD_DIAGNOSE
      if (!g_logged_orch) {
        g_logged_orch = true;
        float *pr = cam_fov_field(kRenderCamIdx);
        float *pf = cam_fov_field(0xf);
        diag("orch entry: cull[0xd]=%g render[0xe]=%g cam[0xf]=%g (g_fov=%g)\n", orig, pr ? *pr : -1.0f,
             pf ? *pf : -1.0f, g_fov);
      }
#endif
      if (orig >= kOverrideLo && orig <= kOverrideHi) {
        *pfov = g_fov;
        g_orch_hook->original(static_cast<orch_fn>(nullptr))(param_1);
        *pfov = orig;
        return;
      }
    }
  }
  g_orch_hook->original(static_cast<orch_fn>(nullptr))(param_1);
}

bool ensure_hook() {
  if (g_hook && g_cull_hook && g_orch_hook) return true;
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
  if (!g_orch_hook) {
    const uintptr_t ofn = g_gfx_base + kOrchRva;
    const bool osig_ok = !IsBadReadPtr(reinterpret_cast<void *>(ofn), 24) &&
                         std::memcmp(reinterpret_cast<void *>(ofn), kOrchSigA, sizeof(kOrchSigA)) == 0 &&
                         std::memcmp(reinterpret_cast<void *>(ofn + 7), kOrchSigB, sizeof(kOrchSigB)) == 0;
#if FOV_MOD_DIAGNOSE
    diag("ensure_hook: orch_fn=0x%08X sig_ok=%d\n", static_cast<unsigned>(ofn), osig_ok ? 1 : 0);
#endif
    if (osig_ok) {
      g_orch_hook = new hook(static_cast<int>(ofn), &orch_detour, hook_type_detour);
#if FOV_MOD_DIAGNOSE
      diag("render orchestrator (full-frame cull bracket) detour INSTALLED at 0x%08X\n",
           static_cast<unsigned>(ofn));
#endif
    }
  }
  return g_hook != nullptr;  // projection is the essential hook; cull + orchestrator are fix-ups
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
  diag("fov_mod install diagnostic (S63: projection + cull + full-frame orchestrator bracket)\n");
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
