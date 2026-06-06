#pragma once

#include <cstdint>

// Theo-and-Co field-of-view control (S62, Phase 1). Widens the camera FOV
// (45-90; default ~45). Our client renders via EQGraphicsDX9.dll, whose C++
// engine dropped the old t3dSetCameraLens export the 2002 client (and upstream
// Zeal) used -- so we hook the DX9 frustum/perspective builder directly:
//
//   EQGraphicsDX9.dll FUN_10006470 (RVA 0x6470) does
//     fov_rad_half = fptan([frustum+4] * deg2rad/2);  -> D3DXMatrixPerspectiveRH
//   i.e. [frustum+4] is the FOV in DEGREES (Ghidra-verified, S62).
//
// We resolve it as GetModuleHandle("EQGraphicsDX9.dll") + 0x6470 (no Ghidra/ASLR
// math -- RVA is fixed), detour it, and while enabled temporarily override
// [frustum+4] with our FOV for the projection compute, then restore it (no
// permanent mutation; /fov off reverts instantly). Persists in zeal.ini
// [Zeal] Fov. Details + RE chain in memory/project_zeal_hide_name_and_commands.md.
namespace fov_mod {

// Best-effort install from dllmain: seeds the saved FOV from zeal.ini and, if
// EQGraphicsDX9.dll is already loaded, installs the frustum hook so the saved
// FOV applies from the first frame. If the DLL isn't loaded yet, the hook is
// installed lazily on the first /fov use. Returns true if the hook went in.
bool install();

// Set the FOV (45-90), enable the override, persist, ensure the hook installs.
// Returns false on out-of-range or if the hook can't install (DLL not ready).
bool set_fov(float fov);

// Revert to the game's default FOV (disable the override) and persist.
void disable();

float get_fov();
bool is_enabled();

}  // namespace fov_mod
