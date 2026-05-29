// fopen / ctime are MSVC-deprecated in favor of fopen_s / ctime_s, but the
// secure variants don't buy us anything for a single-threaded append-only log
// where the file path is a compile-time constant. Define before any includes.
#define _CRT_SECURE_NO_WARNINGS

#include "swim_controls.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <memory>

#include "hook_wrapper.h"

// Phase 1 / R3 Stage 3: hold-to-swim. Session 52 implementation.
// See:
//   memory/PHASE1_CAMERA.md
//   memory/project_zeal_rof2_addresses.md  (BindList / ExecuteCmd / per-frame
//                                          tick address discovery, Session 52)
//
// Problem
// -------
// In RoF2 the JUMP keybind (cmd 1, default Space) fires an upward swim-stroke
// on key-down. While submerged, holding Space does nothing — the player must
// tap the key repeatedly. CMD_MOVE_DOWN (cmd 449, Alex's keybind = Z) has the
// same behavior for swimming downward. Modern MMOs auto-repeat the vertical
// vector while the key is held. This module restores that affordance, gated
// to water only so land-jumps remain single-press.
//
// Mechanism
// ---------
// Two detours, both installed at handle_process_attach() time:
//
//  1) ExecuteCmd  (FUN_004D7230, "the dispatcher")
//     EQ's keypress layer routes every bind through ExecuteCmd(cmd, keydown,
//     aux). Inside, a giant switch on cmd_idx writes a per-cmd state slot in
//     the array at DAT_00de0d88 — case 1 sets slot 1 (JUMP), case 449 sets
//     slot 449 (CMD_MOVE_DOWN). The per-frame movement code reads these
//     slots, applies vertical velocity that frame, and (for JUMP at least)
//     clears the slot — explaining why holding produces a single stroke.
//     Our detour tracks transitions for cmd 1 and cmd 449 (jump_held,
//     move_down_held) and chains to the original. Vanilla behavior is
//     preserved for the initial press; auto-repeat is layered on top.
//
//  2) Per-frame tick  (FUN_0052BBD0, "the input/movement tick")
//     This function runs every frame regardless of camera mode (Session 14
//     finding — calls FUN_00516D40 procMouse internally). Our detour chains
//     to the original first, then evaluates the auto-repeat condition:
//     if (jump_held && in_water && 120ms_elapsed) we call the ORIGINAL
//     ExecuteCmd (bypassing our own detour to avoid a redundant self-
//     state-tracking pass) with cmd=1, keydown=1. Each fire re-arms the
//     state slot for one more frame of vertical velocity. Identical
//     handling for CMD_MOVE_DOWN.
//
// In-water gate
// -------------
// `SwimmingFeetTouchingWater` (entity offset 0xA2, BYTE, 5 = feet touching
// water at any depth) AND `SwimmingWaterType != 7` (offset 0xA1, 7 = lava,
// which we don't want to encourage standing in). This is broader than
// `IsSwimmingUnderwater` (0xA0) — that field is only true when the player
// is fully submerged, but Alex's stated requirement is "any time in water,"
// which includes surface treading.
//
// Cadence: 120ms (~8 strokes/sec) — user-stated preference matching the
// muscle-memory feel of spamming Space.
//
// Recursion guard
// ---------------
// The auto-repeat fire calls the ORIGINAL ExecuteCmd (via hook->original())
// rather than the detour. If it called the detour instead, our detour would
// re-set the held flag to 1 (which is already 1) — harmless but redundant.
// Going through original() also avoids any potential infinite-recursion bug
// if a future change adds bookkeeping that could re-enter the tick.
//
// Diagnostic flag
// ---------------
// Per memory/feedback_diagnostics_from_v1.md, binary-patch features ship
// with diagnostics from v1 — the LMB-pan stabilization arc (S15–S44) made
// the case clearly. Default-on for the dev cycle (this initial build); flip
// to 0 only after Alex verifies behavior is correct and we cut the friend-
// ready release.

// Set to 1 to enable install-time MessageBox + per-fire file logging at
// D:\EQEmu\Full_RoF2\swim_controls_diag.log. Friend builds ship with this 0.
#define ZEAL_ROF2_SWIM_DIAGNOSE 1

namespace swim_controls {

// ---------------- Addresses (Ghidra static, May 10 2013 RoF2 build) -----
// All from classless-dll/eqgame.h cross-verified against this binary in
// Session 52 (build-date string at 0x009dd250 = "May 10 2013").
static const uintptr_t k_execute_cmd_ghidra = 0x004D7230;     // __ExecuteCmd_x
static const uintptr_t k_per_frame_tick_ghidra = 0x0052BBD0;  // FUN_0052bbd0
// Self entity pointer global (the value at this address IS the Entity *).
// Session 14 trace, confirmed via FUN_004d7230's use of DAT_00dd2644-family
// globals. Distinct from DAT_00dd2630 (controlled entity = mount/vehicle).
static const uintptr_t k_self_entity_ptr_ghidra = 0x00DD2644;

// ---------------- Entity field offsets (per Zeal/game_structures.h) -----
static const size_t k_off_swimming_water_type = 0xA1;            // BYTE
static const size_t k_off_swimming_feet_touching_water = 0xA2;   // BYTE

// ---------------- EQ bind cmd indices (Session 52 BindList dump) --------
static const int k_cmd_jump = 1;
static const int k_cmd_move_down = 449;

// ---------------- Auto-repeat cadence -----------------------------------
static const DWORD k_repeat_ms = 120;

// ---------------- Function pointer types --------------------------------
// ExecuteCmd: __cdecl, 3 params. Decompile confirms standard C prologue
// (no ECX/EDX register-passing, SEH frame setup). Returns int (1 on
// successful dispatch, 0 on no-op / early bail).
typedef int(__cdecl *fn_execute_cmd_t)(int cmd, BYTE keydown, unsigned int aux);

// Per-frame tick: signature TBD pending Ghidra decomp of FUN_0052BBD0.
// Stub as __cdecl(void) until Step 17 confirms; adjust to __thiscall/
// __fastcall if the prologue shows ECX-passed `this`.
typedef void(__cdecl *fn_per_frame_t)();

// ---------------- Hook lifetime managers --------------------------------
static std::unique_ptr<hook> g_execute_cmd_hook;
static std::unique_ptr<hook> g_per_frame_hook;

// ---------------- Runtime ASLR-adjusted state ---------------------------
static uintptr_t g_self_entity_runtime = 0;  // Set in install().

// ---------------- Per-cmd held state + repeat schedule ------------------
static bool g_jump_held = false;
static bool g_move_down_held = false;
static DWORD g_next_jump_fire = 0;
static DWORD g_next_move_down_fire = 0;

// ---------------- Diagnostics -------------------------------------------
#if ZEAL_ROF2_SWIM_DIAGNOSE
static void diag_logf(const char *fmt, ...) {
  static FILE *f = nullptr;
  if (!f) {
    f = fopen("D:\\EQEmu\\Full_RoF2\\swim_controls_diag.log", "a");
    if (!f) return;
    fprintf(f, "==== swim_controls log opened (pid=%lu) ====\n", GetCurrentProcessId());
  }
  va_list args;
  va_start(args, fmt);
  vfprintf(f, fmt, args);
  va_end(args);
  fflush(f);
}
#else
static inline void diag_logf(const char *, ...) {}
#endif

// ---------------- Helpers -----------------------------------------------
static void *get_self_entity() {
  if (!g_self_entity_runtime) return nullptr;
  return *reinterpret_cast<void **>(g_self_entity_runtime);
}

// True if the player's feet touch water at ANY depth (surface or submerged),
// AND the water isn't lava. Matches Alex's "any time in water" requirement.
static bool in_water_any_depth() {
  void *self = get_self_entity();
  if (!self) return false;
  char *e = static_cast<char *>(self);
  BYTE feet = *reinterpret_cast<BYTE *>(e + k_off_swimming_feet_touching_water);
  BYTE wtype = *reinterpret_cast<BYTE *>(e + k_off_swimming_water_type);
  return (feet == 5) && (wtype != 7);
}

// ---------------- ExecuteCmd detour -------------------------------------
// Track keydown/keyup for our two cmds, chain to original. Original return
// value is preserved (callers may use it).
static int __cdecl ExecuteCmd_detour(int cmd, BYTE keydown, unsigned int aux) {
  if (cmd == k_cmd_jump) {
    g_jump_held = (keydown != 0);
    diag_logf("[exec] JUMP key=%u held=%d aux=0x%x\n",
              (unsigned)keydown, (int)g_jump_held, aux);
  } else if (cmd == k_cmd_move_down) {
    g_move_down_held = (keydown != 0);
    diag_logf("[exec] MOVE_DOWN key=%u held=%d aux=0x%x\n",
              (unsigned)keydown, (int)g_move_down_held, aux);
  }
  auto orig = g_execute_cmd_hook->original((fn_execute_cmd_t)nullptr);
  return orig(cmd, keydown, aux);
}

// ---------------- Per-frame tick detour ---------------------------------
// Chain to original first (the per-frame movement work needs to run before
// our re-fire so the previous fire's state-slot has had a chance to be
// applied + cleared). Then evaluate the auto-repeat gate.
static void __cdecl PerFrameTick_detour() {
  auto orig = g_per_frame_hook->original((fn_per_frame_t)nullptr);
  orig();

  const DWORD now = GetTickCount();
  const bool in_water = in_water_any_depth();

  if (g_jump_held && in_water && now >= g_next_jump_fire) {
    diag_logf("[tick %lu] fire JUMP\n", now);
    auto orig_exec = g_execute_cmd_hook->original((fn_execute_cmd_t)nullptr);
    orig_exec(k_cmd_jump, 1, 0);
    g_next_jump_fire = now + k_repeat_ms;
  }

  if (g_move_down_held && in_water && now >= g_next_move_down_fire) {
    diag_logf("[tick %lu] fire MOVE_DOWN\n", now);
    auto orig_exec = g_execute_cmd_hook->original((fn_execute_cmd_t)nullptr);
    orig_exec(k_cmd_move_down, 1, 0);
    g_next_move_down_fire = now + k_repeat_ms;
  }
}

// ---------------- Install -----------------------------------------------
bool install(uintptr_t aslr_delta) {
  g_self_entity_runtime = k_self_entity_ptr_ghidra + aslr_delta;
  const uintptr_t exec_cmd_addr = k_execute_cmd_ghidra + aslr_delta;
  const uintptr_t per_frame_addr = k_per_frame_tick_ghidra + aslr_delta;

#if ZEAL_ROF2_SWIM_DIAGNOSE
  char msg[1024];
  wsprintfA(msg,
            "Swim controls install:\r\n"
            "\r\n"
            "ASLR delta: 0x%08x\r\n"
            "\r\n"
            "ExecuteCmd:    ghidra 0x%08x -> runtime 0x%08x\r\n"
            "PerFrameTick:  ghidra 0x%08x -> runtime 0x%08x\r\n"
            "Self entity:   0x%08x (deref for Entity*)\r\n"
            "\r\n"
            "Per-fire log will append to:\r\n"
            "  D:\\EQEmu\\Full_RoF2\\swim_controls_diag.log",
            (unsigned)aslr_delta,
            (unsigned)k_execute_cmd_ghidra, (unsigned)exec_cmd_addr,
            (unsigned)k_per_frame_tick_ghidra, (unsigned)per_frame_addr,
            (unsigned)g_self_entity_runtime);
  MessageBoxA(NULL, msg, "Zeal-RoF2 Swim Controls install",
              MB_OK | MB_ICONINFORMATION);
#endif

  try {
    g_execute_cmd_hook = std::make_unique<hook>(
        (int)exec_cmd_addr, &ExecuteCmd_detour, hook_type_detour);
    g_per_frame_hook = std::make_unique<hook>(
        (int)per_frame_addr, &PerFrameTick_detour, hook_type_detour);
  } catch (...) {
    // hook::detour() throws on signature mismatch / fatal alloc; bail
    // gracefully so the rest of the .asi (Layer 0/1, lmb_pan) still runs.
    return false;
  }

  diag_logf("[install] hooks set, self_ptr=0x%08x, aslr=0x%08x\n",
            (unsigned)g_self_entity_runtime, (unsigned)aslr_delta);
  return true;
}

}  // namespace swim_controls
