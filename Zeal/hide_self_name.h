#pragma once

#include <cstdint>

// Theo-and-Co "hide your own overhead name" (S62, Phase 1). A modern-MMO toggle
// that splits the LOCAL player's floating name out of the client's "Show PC
// Names" setting -- you keep seeing everyone else's (and your bots') names while
// your own is hidden.
//
// Implementation: detour the RoF2 name-sprite show/hide decision function
// (CDisplay/EQPlayer SetNameSpriteState = FUN_0058e2d0, Ghidra-derived vs OUR
// eqgame.exe, S62). When the hide flag is set and the entity is the local
// player, the detour forces show=0 so the client takes its own hide path and
// removes/skips the name sprite. Every other entity is untouched.
//
// Installed directly from dllmain (like lmb_pan / bot_cast_button), NOT via the
// gated-off ZealService (its submodules reference 2002-client addresses wrong
// for our binary). All addresses are Ghidra static (preferred base 0x00400000);
// the runtime ASLR delta is added in install(). Full find-chain + addresses in
// memory/project_zeal_hide_name_and_commands.md.
namespace hide_self_name {

// Installs the SetNameSpriteState detour. Returns false (silent no-op) on a
// prologue signature mismatch (wrong/unknown eqgame.exe build). aslr_delta =
// runtime_base - 0x00400000. Seeds the flag from zeal.ini [Zeal] NameplateHideSelf.
bool install(std::uintptr_t aslr_delta);

// Runtime toggle (the /-command module calls this). Updates the live flag,
// persists it to zeal.ini, and forces an immediate self-nameplate refresh so the
// change shows without a relog.
void set_hidden(bool hidden);
bool is_hidden();

}  // namespace hide_self_name
