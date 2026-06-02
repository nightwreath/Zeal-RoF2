#pragma once

#include <cstdint>

// Theo-and-Co S56: "[Add Button]" bot cast-social feature (pure client-side).
//
// The engine (theo-and-co-engine Bot::ListBotSpells) emits a per-spell
// "[Add Button]" link in `^spells` output. It is a saylink-format link
// (item_id == SAYLINK_ITEM_ID) so clicking it makes the client emit an
// OP_ItemLinkClick packet, with the payload riding the augments:
//   augments[2] = spell id, augments[3] = bot entity id,
//   augments[4] = Zeal marker (kAddCastMarker).
//
// This module intercepts that outgoing packet (existing Zeal SendMessage
// hook -> callback_type::SendMessage_), decodes it, creates a hotbar social
// that force-casts the spell via that specific bot
// (`^cast spellid <id> byname <bot>`), and SUPPRESSES the packet so it never
// reaches the server. A non-Zeal client that clicks the link just gets a
// harmless "say link not found" (augments[0/1] are 0).
//
// Social-store addresses were Ghidra-derived against our eqgame.exe in S55
// (see memory/project_zeal_social_buttons.md).
class BotCastButton {
 public:
  BotCastButton(class ZealService *zeal);
  ~BotCastButton();

 private:
  // Returns true if the packet was ours (decoded + handled -> suppress it).
  bool handle_outgoing_packet(unsigned int opcode, char *buffer, unsigned int len);

  // Writes a one-line social into the first free slot. Returns a 0-based
  // (page * 12 + button) index, or -1 if all candidate slots are full.
  int create_social(const char *label, const char *command_line);

  // S56 diagnostics: prints runtime base + ASLR delta + the cursor-attach
  // pointers. Driven by the reliable /acbinfo chat command (works even if the
  // packet hook does not).
  void print_diag();

  std::uintptr_t aslr_delta_ = 0;  // runtime_base - preferred_base (0x400000)
};
