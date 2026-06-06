#define _CRT_SECURE_NO_WARNINGS

#include "fov_mod.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "hook_wrapper.h"  // standalone `hook` class (detour) -- no ZealService needed

// Ship the diagnostic with v1 (feedback_diagnostics_from_v1.md). When 1,
// install() + ensure_hook() write .\fov_diag.txt with which graphics DLL was
// found, the t3dSetCameraLens address, hook status, and the seeded value -- so
// a not-yet-loaded gfx DLL / missing export surfaces in one launch.
#define FOV_MOD_DIAGNOSE 1

namespace fov_mod {

namespace {

// t3dSetCameraLens(int a1, float fov, float aspect_ratio, float a4, float a5).
// The t3d* graphics API is C-style __cdecl (matches upstream Zeal's hook decl).
// t3d stores CameraInfo.FieldOfView = 0.5 * fov, so to get an effective FOV of
// `v` we pass fov = 2*v.
using lens_fn = int(__cdecl *)(int a1, float fov, float aspect_ratio, float a4, float a5);

constexpr char kZealIni[] = ".\\zeal.ini";
constexpr char kSection[] = "Zeal";
constexpr char kKeyFov[] = "Fov";

constexpr float kMinFov = 45.0f;
constexpr float kMaxFov = 90.0f;
constexpr float kDefaultFov = 45.0f;

hook *g_hook = nullptr;
float g_fov = kDefaultFov;
bool g_enabled = false;

#if FOV_MOD_DIAGNOSE
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

int __cdecl lens_detour(int a1, float fov, float aspect_ratio, float a4, float a5) {
  if (g_enabled) fov = 2.0f * g_fov;  // 2x: t3d halves it internally
  return g_hook->original(static_cast<lens_fn>(nullptr))(a1, fov, aspect_ratio, a4, a5);
}

HMODULE find_gfx_module() {
  HMODULE h = GetModuleHandleA("EQGraphicsDX9.dll");  // what RoF2 loads
  if (!h) h = GetModuleHandleA("eqgfx_dx8.dll");       // legacy fallback
  return h;
}

// Installs the SetCameraLens hook if not already in. Returns true once hooked.
bool ensure_hook() {
  if (g_hook) return true;
  HMODULE gfx = find_gfx_module();
  FARPROC fn = gfx ? GetProcAddress(gfx, "t3dSetCameraLens") : nullptr;
#if FOV_MOD_DIAGNOSE
  diag("ensure_hook: gfx_module=0x%08X t3dSetCameraLens=0x%08X\n", reinterpret_cast<unsigned>(gfx),
       reinterpret_cast<unsigned>(fn));
#endif
  if (!fn) return false;  // gfx DLL not loaded yet, or export missing
  g_hook = new hook(reinterpret_cast<int>(fn), &lens_detour, hook_type_detour);
#if FOV_MOD_DIAGNOSE
  diag("SetCameraLens detour INSTALLED at 0x%08X\n", reinterpret_cast<unsigned>(fn));
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
  diag("fov_mod install diagnostic (S62)\n");
#endif
  // Seed from zeal.ini [Zeal] Fov; a value in range enables the override.
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
  // Try to hook now (graphics DLL is usually loaded by the time .asi loads at
  // sound init). If not, the first /fov use installs it.
  return ensure_hook();
}

}  // namespace fov_mod
