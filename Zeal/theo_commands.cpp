#define _CRT_SECURE_NO_WARNINGS

#include "theo_commands.h"

#include <Windows.h>

#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "hide_self_name.h"
#include "hook_wrapper.h"  // standalone `hook` class (detour) -- no ZealService needed

// Ship the diagnostic with v1 (feedback_diagnostics_from_v1.md). When 1,
// install() writes .\theocmd_diag.txt with base + ASLR delta + signature match
// so a wrong address / non-install / wrong build surfaces in one launch.
#define THEO_COMMANDS_DIAGNOSE 1

namespace theo_commands {

namespace {

// ---- CEverQuest::InterpretCmd, Ghidra-derived + convention-verified vs OUR
//   eqgame.exe (S62, FUN_0051fce0). The typed-command processor: takes the
//   player + the raw command string and dispatches. __thiscall (this in ECX,
//   stack: player, cmd; callee-clean RET 8) -> modeled as __fastcall with a
//   dummy edx, exactly like Zeal's InterpretCommand. Prologue:
//     6A FF             PUSH -1
//     68 2C 85 97 00    PUSH 0x97852C   (SEH handler -- ASLR-relocated)
//     64 A1 00 00 00 00 MOV EAX, FS:[0]
//     50                PUSH EAX
//     64 89 ...         MOV FS:[0], ESP
//   The 4 PUSH-handler bytes are wildcarded in the signature gate. ----
constexpr uintptr_t kInterpretCmdGhidra = 0x0051fce0;
constexpr unsigned char kSig[16] = {0x6A, 0xFF, 0x68, 0, 0, 0, 0, 0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x50, 0x64, 0x89};
constexpr unsigned char kMask[16] = {1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1};
using interpret_fn = void(__fastcall *)(void *eq, int edx, void *player, const char *cmd);

// ---- dsp_chat (client chat-display), Ghidra-derived vs OUR eqgame.exe (S57).
//   void __stdcall(const char* text, int color, int p3, int add_log). 273 =
//   USERCOLOR_DEFAULT (the color of text you type). Reused for our output. ----
constexpr uintptr_t kDspChatGhidra = 0x0051F1A0;
using dsp_chat_fn = void(__stdcall *)(const char *text, int color, int p3, int add_log);
constexpr int kChatColor = 273;

uintptr_t g_aslr_delta = 0;
hook *g_hook = nullptr;

void chat(const char *fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
  va_end(ap);
  auto dsp = reinterpret_cast<dsp_chat_fn>(kDspChatGhidra + g_aslr_delta);
  dsp(buf, kChatColor, 0, 1);
}

std::string lower(std::string s) {
  for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

std::vector<std::string> split_ws(const char *s) {
  std::vector<std::string> out;
  std::string cur;
  for (const char *p = s; *p; ++p) {
    if (*p == ' ' || *p == '\t') {
      if (!cur.empty()) { out.push_back(cur); cur.clear(); }
    } else {
      cur += *p;
    }
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

// ---- command handlers ----
void cmd_hidename(const std::vector<std::string> &args) {
  if (args.size() >= 2) {
    const std::string a = lower(args[1]);
    if (a == "on" || a == "1" || a == "hide") {
      hide_self_name::set_hidden(true);
    } else if (a == "off" || a == "0" || a == "show") {
      hide_self_name::set_hidden(false);
    } else {
      chat("Usage: /hidename [on|off]   (no argument = toggle)");
      return;
    }
  } else {
    hide_self_name::set_hidden(!hide_self_name::is_hidden());
  }
  chat("Your own overhead name is now %s.", hide_self_name::is_hidden() ? "HIDDEN" : "shown");
}

void cmd_zeal(const std::vector<std::string> &args) {
  (void)args;
  chat("Theo & Co commands:");
  chat("   /hidename [on|off]  - hide or show your own overhead name (no arg = toggle)");
  chat("   /zeal               - show this list");
}

struct Command {
  const char *name;
  void (*handler)(const std::vector<std::string> &);
};

const Command kCommands[] = {
    {"/hidename", &cmd_hidename},
    {"/zeal", &cmd_zeal},
};

// Returns true if `cmd` was one of ours (handled + should be suppressed).
bool handle_command(const char *cmd) {
  while (*cmd == ' ' || *cmd == '\t') ++cmd;
  if (*cmd != '/') return false;  // only our slash commands
  const std::vector<std::string> args = split_ws(cmd);
  if (args.empty()) return false;
  const std::string c0 = lower(args[0]);
  for (const Command &c : kCommands) {
    if (c0 == c.name) {
      c.handler(args);
      return true;
    }
  }
  return false;
}

void __fastcall interpret_detour(void *eq, int edx, void *player, const char *cmd) {
  if (cmd && handle_command(cmd)) return;  // ours -> handled, don't reach the client
  g_hook->original(static_cast<interpret_fn>(nullptr))(eq, edx, player, cmd);
}

#if THEO_COMMANDS_DIAGNOSE
void diag(const char *fmt, ...) {
  FILE *f = nullptr;
  fopen_s(&f, ".\\theocmd_diag.txt", "a");
  if (!f) return;
  va_list ap;
  va_start(ap, fmt);
  std::vfprintf(f, fmt, ap);
  va_end(ap);
  std::fclose(f);
}
#endif

}  // namespace

bool install(std::uintptr_t aslr_delta) {
  g_aslr_delta = aslr_delta;
  const uintptr_t runtime = kInterpretCmdGhidra + aslr_delta;

  bool sig_ok = !IsBadReadPtr(reinterpret_cast<const void *>(runtime), sizeof(kSig));
  if (sig_ok) {
    const unsigned char *p = reinterpret_cast<const unsigned char *>(runtime);
    for (size_t i = 0; i < sizeof(kSig); ++i) {
      if (kMask[i] && p[i] != kSig[i]) {
        sig_ok = false;
        break;
      }
    }
  }

#if THEO_COMMANDS_DIAGNOSE
  {
    FILE *f = nullptr;  // truncate fresh each load
    fopen_s(&f, ".\\theocmd_diag.txt", "w");
    if (f) std::fclose(f);
  }
  const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleA(NULL));
  diag("theo_commands install diagnostic (S62)\n");
  diag("base=0x%08X delta=0x%08X\n", static_cast<unsigned>(base), static_cast<unsigned>(aslr_delta));
  diag("InterpretCmd ghidra=0x%08X runtime=0x%08X sig_ok=%d\n", static_cast<unsigned>(kInterpretCmdGhidra),
       static_cast<unsigned>(runtime), sig_ok ? 1 : 0);
  diag("dsp_chat runtime=0x%08X\n", static_cast<unsigned>(kDspChatGhidra + aslr_delta));
#endif

  if (!sig_ok) return false;  // wrong address for this binary -> silent no-op

  g_hook = new hook(runtime, &interpret_detour, hook_type_detour);

#if THEO_COMMANDS_DIAGNOSE
  diag("InterpretCmd detour INSTALLED. commands: /hidename /zeal\n");
#endif
  return true;
}

}  // namespace theo_commands
