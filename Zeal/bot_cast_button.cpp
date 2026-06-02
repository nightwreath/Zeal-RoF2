#define _CRT_SECURE_NO_WARNINGS

#include "bot_cast_button.h"

#include <Windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "hook_wrapper.h"  // standalone `hook` class (detour) -- no ZealService needed
#include "memory.h"

// Ship the diagnostic with v1 (feedback_diagnostics_from_v1.md). When 1,
// install() writes D:\EQEmu\Full_RoF2\acb_diag.txt (delta + signature match +
// dsp_chat runtime address) and the first caught signal line is echoed, so a
// wrong address / non-install surfaces in a single launch. Flip to 0 once
// verified stable in-game.
#define BOT_CAST_BUTTON_DIAGNOSE 1

namespace bot_cast_button {

namespace {

// ---- dsp_chat (client chat-display), Ghidra-derived vs OUR eqgame.exe (S57).
//   void __stdcall dsp_chat(const char* text, int color, int p3, int add_log)
//   359 callers; ends RET 0x10 (callee cleans 4 dword args -> __stdcall).
//   Prologue: 64 A1 00 00 00 00  (mov eax, fs:[0]) -- position-independent, so
//   the same bytes appear at runtime regardless of ASLR -> a stable guard. ----
constexpr uintptr_t kDspChatGhidra = 0x0051F1A0;
const unsigned char kDspChatSig[6] = {0x64, 0xA1, 0x00, 0x00, 0x00, 0x00};
using dsp_chat_fn = void(__stdcall *)(const char *text, int color, int p3, int add_log);

// ---- Engine-agreed signal line (theo-and-co-engine client_packet.cpp, S57).
//   "Bot cast button ready: [<CLS>] <SpellName> via <BotName> (id <spellid>)"
// Must stay byte-identical with the engine's Message() format string prefix. ----
constexpr char kSignalPrefix[] = "Bot cast button ready: [";
constexpr char kViaSep[] = " via ";
constexpr char kIdSep[] = " (id ";

// ---- Social store (Ghidra-derived vs our eqgame.exe, S55). Static
//      (preferred-base 0x400000) addresses; add the runtime ASLR delta. ----
constexpr uintptr_t kSocialRecordsBase = 0x00E15F10;
constexpr uintptr_t kSocialDirtyBase = 0x00E15E98;
constexpr int kSocialButtons = 12;
constexpr int kSocialPageStride = 0x3D50;
constexpr int kSocialRecStride = 0x51C;
constexpr int kSocialNameOff = 0x000;   // 16 bytes (15 chars + null)
constexpr int kSocialLine1Off = 0x010;  // 256 bytes
constexpr int kSocialColorOff = 0x510;  // 1 byte
constexpr int kSocialDirtyStride = 0x0C;
constexpr uint8_t kSocialColor = 0;  // matches launcher-managed buttons (Color=0)

// Candidate social PAGES (0-based), in fill order (Alex-locked S57). Dedicate
// the free overflow pages 7-9 (in-game "Page 8-10") to auto-created cast
// buttons so they stay grouped and OFF the player's personal Page 1; page 0
// (in-game "Page 1") is the last-resort fallback once 8-10 fill (~36 slots).
// Launcher-managed pages 1-6 (in-game "Page 2-7": bot command + create
// buttons) are never touched.
constexpr int kCandidatePages[] = {7, 8, 9, 0};

uintptr_t g_aslr_delta = 0;
hook *g_dsp_hook = nullptr;

#if BOT_CAST_BUTTON_DIAGNOSE
bool g_logged_first_catch = false;
void diag_file(const char *fmt, ...) {
  FILE *f = nullptr;
  fopen_s(&f, "D:/EQEmu/Full_RoF2/acb_diag.txt", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(f, fmt, ap);
  va_end(ap);
  std::fclose(f);
}
#endif

// Writes a one-line social into the first free candidate slot. Returns a
// 0-based (page*12 + button) index, or -1 if all candidate slots are full.
int create_social(const char *label, const char *command_line) {
  for (int page : kCandidatePages) {
    for (int b = 0; b < kSocialButtons; ++b) {
      const uintptr_t rec =
          kSocialRecordsBase + g_aslr_delta + page * kSocialPageStride + b * kSocialRecStride;
      const char *existing = reinterpret_cast<const char *>(rec + kSocialNameOff);
      if (existing[0] != '\0') continue;  // slot occupied

      // Clear the whole record so a previously-deleted slot can't leave stale
      // Line2-5 commands attached to our one-line social.
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

      const uintptr_t dirty = kSocialDirtyBase + g_aslr_delta + page * kSocialDirtyStride + b;
      mem::write<uint8_t>(static_cast<int>(dirty), 1);

      return page * kSocialButtons + b;
    }
  }
  return -1;
}

// Parses the engine signal line and builds the social. Returns true if `text`
// was our signal (caller suppresses the raw line + shows a clean confirmation).
bool handle_signal_line(const char *text, int color, int p3, int add_log) {
  if (!text) return false;
  const size_t plen = sizeof(kSignalPrefix) - 1;
  if (std::strncmp(text, kSignalPrefix, plen) != 0) return false;  // not our line

#if BOT_CAST_BUTTON_DIAGNOSE
  if (!g_logged_first_catch) {
    g_logged_first_catch = true;
    diag_file("first signal caught: \"%s\"\n", text);
  }
#endif

  std::string s(text);
  // "Bot cast button ready: [<CLS>] <SpellName> via <BotName> (id <spellid>)"
  const size_t cls_beg = plen;  // first char after the '['
  const size_t cls_end = s.find(']', cls_beg);
  if (cls_end == std::string::npos) return false;
  const std::string cls = s.substr(cls_beg, cls_end - cls_beg);

  size_t name_beg = cls_end + 1;
  if (name_beg < s.size() && s[name_beg] == ' ') ++name_beg;  // skip "] "

  const size_t via = s.find(kViaSep, name_beg);
  if (via == std::string::npos) return false;
  const std::string spell_name = s.substr(name_beg, via - name_beg);

  const size_t bot_beg = via + (sizeof(kViaSep) - 1);
  const size_t id_mark = s.find(kIdSep, bot_beg);
  if (id_mark == std::string::npos) return false;
  const std::string bot_name = s.substr(bot_beg, id_mark - bot_beg);

  const size_t id_beg = id_mark + (sizeof(kIdSep) - 1);
  const size_t id_end = s.find(')', id_beg);
  if (id_end == std::string::npos) return false;
  const int spell_id = std::atoi(s.substr(id_beg, id_end - id_beg).c_str());
  if (spell_id <= 0 || bot_name.empty() || cls.empty()) return false;

  // Label "<CLS> <SpellName>", hard-truncated to 15 (social Name field).
  std::string label = cls + " " + spell_name;
  if (label.size() > 15) label.resize(15);
  const std::string line = "^cast spellid " + std::to_string(spell_id) + " byname " + bot_name;

  const int slot = create_social(label.c_str(), line.c_str());

  // Suppress the raw signal; show a clean confirmation via the ORIGINAL
  // dsp_chat (bypasses our detour -> no recursion).
  char confirm[200];
  if (slot >= 0) {
    _snprintf_s(confirm, sizeof(confirm), _TRUNCATE,
                "Bot cast button created: %s -- open Socials and drag it onto a hotbar.", label.c_str());
  } else {
    _snprintf_s(confirm, sizeof(confirm), _TRUNCATE,
                "Couldn't create that bot cast button: no free social slots (free one and retry).");
  }
  if (g_dsp_hook) {
    g_dsp_hook->original(static_cast<dsp_chat_fn>(nullptr))(confirm, color, p3, add_log);
  }
  return true;
}

void __stdcall dsp_chat_detour(const char *text, int color, int p3, int add_log) {
  if (handle_signal_line(text, color, p3, add_log)) return;  // ours -> suppressed
  if (g_dsp_hook) {
    g_dsp_hook->original(static_cast<dsp_chat_fn>(nullptr))(text, color, p3, add_log);
  }
}

}  // namespace

bool install(std::uintptr_t aslr_delta) {
  g_aslr_delta = aslr_delta;
  const uintptr_t runtime = kDspChatGhidra + aslr_delta;

  const bool sig_ok =
      !IsBadReadPtr(reinterpret_cast<const void *>(runtime), sizeof(kDspChatSig)) &&
      std::memcmp(reinterpret_cast<const void *>(runtime), kDspChatSig, sizeof(kDspChatSig)) == 0;

#if BOT_CAST_BUTTON_DIAGNOSE
  // Fresh file each load (truncate), then append.
  {
    FILE *f = nullptr;
    fopen_s(&f, "D:/EQEmu/Full_RoF2/acb_diag.txt", "w");
    if (f) std::fclose(f);
  }
  const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
  diag_file("ACB install diagnostic (S57 server-signal)\n");
  diag_file("base=0x%08X delta=0x%08X\n", static_cast<unsigned>(base), static_cast<unsigned>(aslr_delta));
  diag_file("dsp_chat ghidra=0x%08X runtime=0x%08X sig_ok=%d\n", static_cast<unsigned>(kDspChatGhidra),
            static_cast<unsigned>(runtime), sig_ok ? 1 : 0);
  diag_file("social rec0 (delta-adjusted)=0x%08X\n",
            static_cast<unsigned>(kSocialRecordsBase + aslr_delta));
#endif

  if (!sig_ok) return false;  // wrong address for this binary -> silent no-op

  g_dsp_hook = new hook(runtime, &dsp_chat_detour, hook_type_detour);

#if BOT_CAST_BUTTON_DIAGNOSE
  diag_file("dsp_chat detour INSTALLED.\n");
#endif
  return true;
}

}  // namespace bot_cast_button
