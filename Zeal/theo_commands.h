#pragma once

#include <cstdint>

// Theo-and-Co slash-command dispatcher (S62, Phase 1). Unlocks in-game `/`
// commands on our RoF2 eqgame.exe by detouring CEverQuest::InterpretCmd
// (FUN_0051fce0, Ghidra-derived/convention-verified vs OUR binary). Zeal's own
// command system never works here because it only constructs under the gated-off
// ZealService AND its inherited fn_interpretcmd address (0x54572f) is wrong for
// our binary -- so this is a clean, standalone dispatcher installed directly
// from dllmain (the lmb_pan / bot_cast_button pattern).
//
// Registered commands (extend kCommands in the .cpp to add more):
//   /hidename [on|off]  toggle/set hiding your own overhead name
//   /zeal               list the Theo & Co custom commands
//
// Typed commands that aren't ours are passed straight through to the client's
// own InterpretCmd, so nothing the client normally handles is affected.
namespace theo_commands {

// Installs the InterpretCmd detour. Returns false (silent no-op) on a prologue
// signature mismatch. aslr_delta = runtime_base - 0x00400000.
bool install(std::uintptr_t aslr_delta);

}  // namespace theo_commands
