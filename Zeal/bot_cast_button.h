#pragma once

#include <cstdint>

// Theo-and-Co "[Add Button]" bot cast-social (S56 feature; S57 server-signal
// redesign).
//
// The engine (theo-and-co-engine Bot::ListBotSpells) emits a per-spell
// "[Add Button]" link in `^spells`. Clicking it sends an OP_ItemLinkClick to
// the SERVER (the S56 pure-client intercept is impossible on our eqgame.exe:
// Zeal's inherited outgoing-packet hook address is wrong and the client's net
// send layer is vtable-indirect). The server's Handle_OP_ItemLinkClick detects
// the marker (augments[4]==0xADDCA) and replies with a confirmation line:
//
//   "Bot cast button ready: [<CLS>] <SpellName> via <BotName> (id <spellid>)"
//
// This module detours dsp_chat (the client chat-display function, S57
// Ghidra-derived = FUN_0051f1a0) to catch that line, parse it, create a
// hotbar social running "^cast spellid <id> byname <bot>", and suppress the
// raw line (replacing it with a clean confirmation). On a non-Zeal/old client
// the player just sees the harmless "ready" line.
//
// Installed directly from dllmain (like lmb_pan), NOT via ZealService, which
// is gated off (its submodules reference 2002-client addresses wrong for our
// binary). Social-store + dsp_chat addresses were Ghidra-derived against OUR
// eqgame.exe (memory/project_zeal_social_buttons.md).
namespace bot_cast_button {

// Installs the dsp_chat detour. Returns false (silent no-op) on a prologue
// signature mismatch. aslr_delta = runtime_base - 0x00400000.
bool install(std::uintptr_t aslr_delta);

}  // namespace bot_cast_button
