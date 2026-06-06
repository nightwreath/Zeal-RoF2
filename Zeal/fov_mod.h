#pragma once

#include <cstdint>

// Theo-and-Co field-of-view control (S62, Phase 1). Widens the camera FOV
// (45-90; default ~45) by hooking t3dSetCameraLens -- the graphics-engine
// function the client calls every frame to set up the 3D projection -- and
// overriding its fov argument. A one-time write to CameraInfo.FieldOfView would
// be clobbered by the next frame's SetCameraLens call, so the per-frame hook is
// the robust path (this mirrors upstream Zeal's /fov).
//
// t3dSetCameraLens is a NAMED EXPORT of the graphics DLL, so unlike the rest of
// our hooks it needs no Ghidra address / ASLR math -- GetProcAddress gives the
// real runtime address. Our client loads EQGraphicsDX9.dll (not the 2002
// client's eqgfx_dx8.dll that upstream Zeal looks up), so we try the DX9 name
// first with the DX8 name as a fallback. Persists the choice in zeal.ini
// [Zeal] Fov. See memory/project_zeal_hide_name_and_commands.md.
namespace fov_mod {

// Best-effort install from dllmain: seeds the saved FOV from zeal.ini and, if
// the graphics DLL is already loaded, installs the SetCameraLens hook so the
// saved FOV applies from the first frame. If the DLL isn't loaded yet, the hook
// is installed lazily on the first /fov use (set_fov -> ensure_hook). Returns
// true if the hook went in.
bool install();

// Set the FOV (45-90), enable the override, persist, and ensure the hook is
// installed. Returns false on an out-of-range value or if the hook can't be
// installed (graphics DLL/export missing).
bool set_fov(float fov);

// Revert to the game's default FOV (disable the override) and persist.
void disable();

float get_fov();
bool is_enabled();

}  // namespace fov_mod
