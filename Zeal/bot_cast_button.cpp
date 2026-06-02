#include "bot_cast_button.h"

#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "callbacks.h"
#include "commands.h"
#include "game_addresses.h"
#include "game_functions.h"
#include "game_structures.h"
#include "game_ui.h"
#include "memory.h"
#include "zeal.h"

// Ship the diagnostic with v1 (feedback_diagnostics_from_v1.md). Flip to 0
// once the feature is verified stable in-game. When 1, every saylink click is
// logged with its full augment payload so the wire format (and a wrong
// social-store address) surfaces in a single launch.
#define BOT_CAST_BUTTON_DIAGNOSE 1

namespace {

// ---- Wire / engine-agreed constants (MUST match theo-and-co-engine) ----
constexpr unsigned int kOpItemLinkClick = 0x4cef;   // RoF2 client->server (utils/patches/patch_RoF2.conf:262)
constexpr uint32_t kSaylinkItemId = 0xFFFFF;        // common/features.h SAYLINK_ITEM_ID
constexpr uint32_t kAddCastMarker = 0xADDCA;        // bot.cpp ListBotSpells augments[4]

// ---- Social store (Ghidra-derived vs our eqgame.exe, S55). These are static
//      (preferred-base 0x400000) addresses; add the runtime ASLR delta. ----
constexpr uintptr_t kSocialRecordsBase = 0x00E15F10;
constexpr uintptr_t kSocialDirtyBase = 0x00E15E98;
constexpr int kSocialButtons = 12;
constexpr int kSocialPageStride = 0x3D50;
constexpr int kSocialRecStride = 0x51C;
constexpr int kSocialNameOff = 0x000;    // 16 bytes (15 chars + null)
constexpr int kSocialLine1Off = 0x010;   // 256 bytes
constexpr int kSocialColorOff = 0x510;   // 1 byte
constexpr int kSocialDirtyStride = 0x0C;  // per page; + button index
constexpr uint8_t kSocialColor = 0;       // matches Launch_EQ.ps1 managed buttons (Color=0)

// Candidate social PAGES (0-based) for new cast-buttons, in priority order.
// Page 0 (the in-game "Page 1") is the player's page -- always visible and
// never touched by the launcher, so the drag-to-bar MVP is verifiable there.
// Pages 7-9 ("Page 8-10") are dedicated overflow. Launcher pages 1-6
// ("Page 2-7") are deliberately skipped -- the launcher prunes them.
constexpr int kCandidatePages[] = {0, 7, 8, 9};

// EQ client->server item-link-click payload (engine ItemViewRequest_Struct, 52 bytes).
#pragma pack(push, 1)
struct ItemViewRequest {
  uint32_t item_id;         // 0x00
  uint32_t augments[6];     // 0x04
  uint32_t link_hash;       // 0x1C
  uint32_t unknown028;      // 0x20
  char unknown032[12];      // 0x24
  uint16_t icon;            // 0x30
  char unknown046[2];       // 0x32
};                          // 0x34 (52)
#pragma pack(pop)
static_assert(sizeof(ItemViewRequest) == 52, "ItemViewRequest must be 52 bytes");

const char *class_code(int class_id) {
  switch (class_id) {
    case 1: return "WAR";
    case 2: return "CLR";
    case 3: return "PAL";
    case 4: return "RNG";
    case 5: return "SHD";
    case 6: return "DRU";
    case 7: return "MNK";
    case 8: return "BRD";
    case 9: return "ROG";
    case 10: return "SHM";
    case 11: return "NEC";
    case 12: return "WIZ";
    case 13: return "MAG";
    case 14: return "ENC";
    case 15: return "BST";
    default: return "BOT";
  }
}

}  // namespace

int BotCastButton::create_social(const char *label, const char *command_line) {
  for (int page : kCandidatePages) {
    for (int b = 0; b < kSocialButtons; ++b) {
      const uintptr_t rec =
          kSocialRecordsBase + aslr_delta_ + page * kSocialPageStride + b * kSocialRecStride;
      const char *existing = reinterpret_cast<const char *>(rec + kSocialNameOff);
      if (existing[0] != '\0') continue;  // slot occupied

      // Clear the whole record first so a previously-deleted slot can't leave
      // stale Line2-5 commands attached to our one-line social.
      mem::set(static_cast<int>(rec), 0, kSocialRecStride);

      char namebuf[16] = {0};
      size_t name_len = std::strlen(label);
      if (name_len > sizeof(namebuf) - 1) name_len = sizeof(namebuf) - 1;
      std::memcpy(namebuf, label, name_len);
      mem::write(static_cast<int>(rec + kSocialNameOff), namebuf);

      char linebuf[256] = {0};
      size_t line_len = std::strlen(command_line);
      if (line_len > sizeof(linebuf) - 1) line_len = sizeof(linebuf) - 1;
      std::memcpy(linebuf, command_line, line_len);
      mem::write(static_cast<int>(rec + kSocialLine1Off), linebuf);

      mem::write<uint8_t>(static_cast<int>(rec + kSocialColorOff), kSocialColor);

      const uintptr_t dirty =
          kSocialDirtyBase + aslr_delta_ + page * kSocialDirtyStride + b;
      mem::write<uint8_t>(static_cast<int>(dirty), 1);

      return page * kSocialButtons + b;
    }
  }
  return -1;
}

bool BotCastButton::handle_outgoing_packet(unsigned int opcode, char *buffer, unsigned int len) {
#if BOT_CAST_BUTTON_DIAGNOSE
  // One-shot: confirms the SendMessage hook actually fires on our binary (if
  // this never appears, the hook address 0x54e51a is wrong at runtime or the
  // item-link-click takes a different send path).
  static bool announced = false;
  if (!announced) {
    announced = true;
    Zeal::Game::print_chat(USERCOLOR_SPELLS, "[ACB] tx-hook LIVE (first packet seen).");
  }
  // Low-noise: only log packets the size of an item-link-click (52) or the
  // expected opcode, so the [Add Button] click stands out.
  if (len == sizeof(ItemViewRequest) || opcode == kOpItemLinkClick) {
    Zeal::Game::print_chat("[ACB tx] op=0x%X len=%u first4=0x%08X", opcode, len,
                           (len >= 4 && buffer) ? *reinterpret_cast<unsigned int *>(buffer) : 0u);
  }
#endif
  if (opcode != kOpItemLinkClick || len != sizeof(ItemViewRequest) || !buffer) return false;
  auto *ivr = reinterpret_cast<ItemViewRequest *>(buffer);
  if (ivr->item_id != kSaylinkItemId) return false;  // not a saylink-format link

#if BOT_CAST_BUTTON_DIAGNOSE
  Zeal::Game::print_chat(
      "[AddButton diag] saylink click aug=[%u,%u,%u,%u,%u,%u] hash=0x%X delta=0x%X",
      ivr->augments[0], ivr->augments[1], ivr->augments[2], ivr->augments[3], ivr->augments[4],
      ivr->augments[5], ivr->link_hash, static_cast<unsigned int>(aslr_delta_));
#endif

  if (ivr->augments[4] != kAddCastMarker) return false;  // a normal saylink -> let it reach the server

  // Our [Add Button] click. Decode -> build the social -> suppress the packet.
  const uint16_t spell_id = static_cast<uint16_t>(ivr->augments[2]);
  const uint16_t bot_id = static_cast<uint16_t>(ivr->augments[3]);

#if BOT_CAST_BUTTON_DIAGNOSE
  // Cursor-attach feasibility probe (S56). ChatManager is the control: chat
  // works, so it must be a sane pointer. If CursorAttachment is a similar
  // (non-null, heap-range) pointer, Windows->CursorAttachment resolves on our
  // binary and the deluxe cursor-attach needs only the attach FUNCTION. Reading
  // the table slots is safe; we do NOT dereference the result here.
  if (Zeal::Game::Windows) {
    Zeal::Game::print_chat("[AddButton diag] Windows=0x%X ChatMgr=0x%X CursorAttach=0x%X",
                           reinterpret_cast<uintptr_t>(Zeal::Game::Windows),
                           reinterpret_cast<uintptr_t>(Zeal::Game::Windows->ChatManager),
                           reinterpret_cast<uintptr_t>(Zeal::Game::Windows->CursorAttachment));
  }
#endif

  Zeal::GameStructures::Entity *bot = Zeal::Game::get_entity_by_id(static_cast<short>(bot_id));
  if (!bot) {
    Zeal::Game::print_chat(
        USERCOLOR_SHOUT,
        "[Add Button] That bot is no longer in the zone -- reopen its spell list (^spells) and try again.");
    return true;
  }

  const auto *spell_mgr = Zeal::Game::get_spell_mgr();
  const auto *spell =
      (spell_mgr && Zeal::Game::Spells::IsValidSpellIndex(spell_id)) ? spell_mgr->Spells[spell_id] : nullptr;
  const char *spell_name = (spell && spell->Name) ? spell->Name : "Spell";

  // Label: "<CLS> <SpellName>", ALL-CAPS class code, hard-truncated to 15.
  std::string label = class_code(bot->Class);
  label += ' ';
  label += spell_name;
  if (label.size() > 15) label.resize(15);

  std::string line = "^cast spellid " + std::to_string(spell_id) + " byname " + bot->Name;

  const int slot = create_social(label.c_str(), line.c_str());
  if (slot < 0) {
    Zeal::Game::print_chat(USERCOLOR_SHOUT,
                           "[Add Button] No free social slots -- free one and try again.");
  } else {
#if BOT_CAST_BUTTON_DIAGNOSE
    Zeal::Game::print_chat(USERCOLOR_SPELLS,
                           "[Add Button] Created social '%s' (slot %d): %s. Open Socials and drag it onto a hotbar.",
                           label.c_str(), slot, line.c_str());
#else
    Zeal::Game::print_chat(USERCOLOR_SPELLS,
                           "[Add Button] Created social '%s' -- open Socials and drag it onto a hotbar.",
                           label.c_str());
#endif
  }
  return true;  // suppress: the marker packet never reaches the server
}

void BotCastButton::print_diag() {
  FILE *f = nullptr;
  fopen_s(&f, "D:/EQEmu/Full_RoF2/acb_diag.txt", "w");
  if (!f) return;
  const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
  std::fprintf(f, "ACB load diagnostic (S56)\n");
  std::fprintf(f, "base=0x%08X delta=0x%08X\n", static_cast<unsigned>(base), static_cast<unsigned>(aslr_delta_));

  // Bytes at the inherited hook targets. They live in .text; with ASLR the raw
  // addresses may land elsewhere, so guard every read. A clean function
  // prologue (e.g. 8B FF 55 8B EC) means plausibly-right; garbage/unreadable
  // means the inherited address is wrong for our binary.
  auto report = [f](const char *label, uintptr_t a) {
    const unsigned char *p = reinterpret_cast<const unsigned char *>(a);
    if (!IsBadReadPtr(p, 6)) {
      std::fprintf(f, "%s @0x%08X: %02X %02X %02X %02X %02X %02X\n", label, static_cast<unsigned>(a), p[0], p[1],
                   p[2], p[3], p[4], p[5]);
    } else {
      std::fprintf(f, "%s @0x%08X: <unreadable>\n", label, static_cast<unsigned>(a));
    }
  };
  report("send(0x54E51A)", 0x0054E51A);  // inherited SendMessage hook target
  report("cmd (0x54572F)", 0x0054572F);  // inherited InterpretCmd hook target
  report("win (0x63D5CC)", 0x0063D5CC);  // inherited window-manager table base
  std::fprintf(f, "social rec0 (delta-adjusted)=0x%08X\n", static_cast<unsigned>(kSocialRecordsBase + aslr_delta_));
  std::fclose(f);
}

BotCastButton::BotCastButton(ZealService *zeal) {
  aslr_delta_ = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL)) - 0x00400000;

  zeal->callbacks->AddPacket(
      [this](UINT opcode, char *buffer, UINT len) { return handle_outgoing_packet(opcode, buffer, len); },
      callback_type::SendMessage_);

#if BOT_CAST_BUTTON_DIAGNOSE
  // The inherited command + packet-send hooks are unreliable on our binary, so
  // chat/command diagnostics can't be trusted. Write a load-time diagnostic to
  // a file from the ctor (which runs whenever Zeal loads) -- the reliable
  // channel for the ASLR delta + the state of the inherited hook addresses.
  print_diag();
#endif
}

BotCastButton::~BotCastButton() {}
