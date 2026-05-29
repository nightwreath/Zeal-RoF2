#pragma once
#include <cstdint>

namespace swim_controls {

// Install the ExecuteCmd + per-frame-tick detours that drive hold-to-swim.
// Returns true if both hooks installed cleanly. Called once from
// handle_process_attach() after aslr_delta is computed.
bool install(uintptr_t aslr_delta);

}  // namespace swim_controls
