## I. Vulnerability Trigger Environment and Preconditions (Trigger)

**Nanomq Version:**
```
commit 2d80f7cff59fab51ec1b7bfe478e3860af91fc39 (HEAD -> master, origin/master, origin/HEAD)
Author: Jaylin <jaylin@emqx.io>
Date:   Wed Jan 21 18:24:49 2026 +0800

    * MDF [nng] new 0.24.9 release

    Signed-off-by: Jaylin <jaylin@emqx.io>

```

* **Build Environment State**: Compiled without SQLite dependencies (`NNG_SUPP_SQLITE` macro is undefined); the underlying SQLite handling code is excluded from the build..
* **Runtime Configuration State**: The persistence option is manually set to true in the configuration file `nanomq.conf` (`sqlite.enable = true`).
* **Trigger Action**: The client establishes an MQTT connection and continuously sends Publish messages with QoS > 0.

**PoC Script:** See `249exploit_leak.py`.

**PoC Script Description (`249exploit_leak.py`):**
This script simulates the MQTT interaction flow by constructing raw TCP packets. The script simultaneously launches two clients:

1. **Subscriber (Client 1)**: Subscribes to a specific topic and **maintains a persistent connection**, simulating a normal receiver.
2. **Publisher (Client 2)**: Sends a **QoS 1** Publish message. It is precisely this QoS > 0 message that forces the Broker to enter the persistence handling flow (i.e., the vulnerability trigger path), thereby causing a memory leak due to the invalid database pointer.

Please refer to my previous comment for the reproduction Dockerfile and related files.


## II. Memory Object Lifecycle Baseline (Baseline: 3 Clones vs 3 Frees)

### 2.1. Leak Source Identification (ASAN Analysis)

The AddressSanitizer (ASAN) detection report identified the source of the memory leak at the call site of `nni_msg_alloc`:

* **Function Location**: `tcptran_pipe_recv_cb`
* **File Path**: `nng/src/sp/transport/mqtt/broker_tcp.c`

```c
if ((rv = nni_msg_alloc(&p->rxmsg, (size_t) len)) != 0) {
    log_warn("Mem error %ld\n", (size_t) len);
    log_warn("LEAK_HUNT: Alloc new msg at %p", p->rxmsg);
    rv = NMQ_SERVER_UNAVAILABLE;
    goto recv_error;
}

```

### 2.2 Memory Management Mechanism Analysis

Through analysis of the Nanomq source code, I confirmed that its core message structure, `nni_msg`, employs a **Reference Counting** mechanism to manage its lifecycle.

* **Alloc**: Uses `nni_msg_alloc` for initial memory allocation, initializing the reference count to 1.
* **Clone**: When the message needs to be shared across different modules or logical flows, `nni_msg_clone` is called, which atomically increments the reference count (+1).
* **Free**: Uses `nni_msg_free` to release the message. This function first performs `nni_atomic_dec_nv(&m->m_refcnt)` to atomically decrement the reference count. **Only when the reference count reaches zero** is `free` actually called to release the physical memory.

The critical logic of `nni_msg_free` is as follows:

```c
// Only actually free memory when reference count drops to 0
if ((m != NULL) && (nni_atomic_dec_nv(&m->m_refcnt) == 0)) {
    nni_chunk_free(&m->m_body);
    if (m->m_proto_ops != NULL && m->m_proto_ops->msg_free != NULL) {
        m->m_proto_ops->msg_free(m->m_proto_data);
    }
    NNI_FREE_STRUCT(m);
}

```

The involved data structure `nng_msg` is defined as follows, where `m_refcnt` is the key member controlling the lifecycle:

```c
struct nng_msg {
    uint32_t  m_header_buf[(NNI_MAX_MAX_TTL + 1)]; // only Fixed header
    size_t    m_header_len;
    nni_chunk m_body; // equal to variable header + payload
    nni_proto_msg_ops *m_proto_ops;
    void * m_proto_data;
    uint32_t           m_pipe; // set on receive
    nni_atomic_int     m_refcnt;// Alloc=1, Clone++, Free--
    // FOR NANOMQ
    uint8_t          CMD_TYPE;
    uint8_t * payload_ptr; // payload
    nni_time         times;       // the time msg arrives
    conn_param      *cparam;      // indicates where it originated
};

```

### 2.3 Debugging Methodology and Object Tracing (Methodology & Trace)

Since reproducing the vulnerability relies on high-concurrency requests from an attack script and the server must maintain real-time responsiveness, GDB debugging is impractical due to timing constraints. Therefore, I adopted a Dynamic Instrumentation analysis method.

I inserted tracing code into the `nni_msg_alloc`, `nni_msg_clone`, and `nni_msg_free` functions to record operation types and call stacks (resolved via `addr2line`).

While reproducing the PUBLISH message processing flow, I captured a typical leaked object with the memory address `0x60e00002ffa0`. Based on the cross-validation of the ASAN report and instrumentation logs, it is confirmed that this object is indeed the leak point. Below is the complete lifecycle trace record for this memory object:

### 2.4 Lifecycle Summary of Memory Object `0x60e00002ffa0`

Based on the complete code logic, log traces, and ASan report, the lifecycle of memory object `0x60e00002ffa0` is summarized in the order of **"Three Time +1"** and **"Two Time -1"**.

#### 1. Alloc (+1) —— [Corresponds to Free 2]

* **Action**: Transport layer receives a network packet and allocates initial memory.
* **File**: `nanomq/nng/src/sp/transport/mqtt/broker_tcp.c`
* **Function**: `tcptran_pipe_recv_cb`
* **Log**: `[LIFE_CYCLE] BORN: msg 0x60e00002ffa0 allocated`
* **Current Ref**: **1**
* **Ownership**: This reference ownership is passed by `aio` to the application layer `server_cb` and should ultimately be freed by the application layer.

#### 2. Clone 1 (+1) —— [Corresponds to Free 1]

* **Action**: Application layer (Broker) clones a copy for sending to distribute (Publish) the message to subscribers.
* **File**: `nanomq/nanomq/apps/broker.c`
* **Function**: `server_cb` (inside `case WAIT` loop)
* **Log**: `server_cb: [TRACE Clone] 1 WAIT -PUBLISH Sending smsg. Cloning Msg: 0x60e00002ffa0`
* **Current Ref**: **2**
* **Ownership**: This reference ownership is handed over to the underlying transport layer for the actual network transmission task.

#### 3. Clone 2 (+1) —— [No Corresponding Free]

* **Action**: Before sending a QoS=1 message, the underlying transport layer clones another copy for the persistence/retransmission mechanism.
* **File**: `nanomq/nng/src/sp/transport/mqtt/broker_tcp.c`
* **Function**: `nmq_pipe_send_start_v4`
* **Code**: `if (qos > 0 && pid == 0) { ... nni_msg_clone(msg); ... }`
* **Log**: `nmq_pipe_send_start_v4: [TRACE CLONE] 2 . Cloning Msg: 0x60e00002ffa0`
* **Current Ref**: **3**
* **Ownership**: This reference ownership should theoretically be released after receiving the PUBACK.

#### 4. Free 1 (-1) —— [Consumes Clone 1]

* **Action**: Underlying TCP send callback completes execution, releasing the reference held by the send task.
* **File**: `nanomq/nng/src/sp/transport/mqtt/broker_tcp.c`
* **Function**: `nmq_tcptran_pipe_send_cb`
* **Log**: `[TRACE SPOT 1] TCP Transport Layer (Send CB) is freeing: 0x60e00002ffa0`
* **Current Ref**: **3 -> 2**
* **Explanation**: Network transmission is complete, and the reference generated by Clone 1 is correctly reclaimed.

#### 5. Free 2 (-1) —— [Consumes Alloc]

* **Action**: Application layer distribution logic ends completely, releasing the original reference held by the application layer.
* **File**: `nanomq/nanomq/apps/broker.c`
* **Function**: `server_cb` (before `case WAIT` ends)
* **Log**: `[TRACE SPOT 2] Broker App Layer (Server CB) is freeing: 0x60e00002ffa0`
* **Current Ref**: **2 -> 1**
* **Explanation**: Business logic is complete, and the reference generated by Alloc is correctly reclaimed.
### Final Conclusion

* **Total Allocations**: 1 (Alloc) + 1 (Clone 1) + 1 (Clone 2) = **3**
* **Total Releases**: 1 (Free 1) + 1 (Free 2) = **2**
* **Cause of Leak**: **Clone 2** (generated in `nmq_pipe_send_start_v4`) lacks a corresponding **Free 3**. The reference count ultimately remains at **1**, rendering the memory unrecoverable.
### 2.5 Supplementary Verification: Ruling Out Missing PUBACK Interference

After identifying the unreleased **Clone 2**, I initially suspected that the leak might be an artifact of my PoC script. To simplify the reproduction, the PoC does not send a `PUBACK` after the `PUBLISH` message. I reasoned that the server might be intentionally holding the reference while awaiting QoS confirmation.

To rule out this possibility, I conducted a comparative test using a standard Nanomq client (which executes the full QoS flow and sends `PUBACK`). The results confirmed that **the memory leak persists even when the server receives the `PUBACK`.**

This observation, combined with ASAN's detection mechanism (which reports "orphaned" memory that is no longer referenced by any pointer), further confirms the root cause:
The issue is not whether the server receives a `PUBACK`, but rather that the program **loses the pointer to the memory object** the moment the "Early Return" occurs in `nni_qos_db_set`. Due to this lost pointer, the subsequent `PUBACK` processing logic cannot address or retrieve the object to release it. Consequently, the memory remains allocated but inaccessible, which is why ASAN accurately flags it as a leak.

The diagram below illustrates the complete process (incorporating the analysis from Sections III and IV):
![[mermaid-diagram.png]]
## III. Root Cause Analysis: The Origin and Propagation of "DB Pointer is NULL"

We summarize the analysis process of the core root cause into three stages: **Missing Macro Definition**, **Inconsistency between Configuration and Environment**, and **Silent Return inside Function**.

By comparing the instrumentation logs with the code logic, it can be confirmed that the `db` pointer was never correctly initialized during runtime.

**1. Origin: Missing Compilation Macro Causes Initialization Logic to be Stripped (`nano_sock_setdb`)**

Comparing code logic with actual runtime logs:

* **Code Logic**:

```c
// ...
log_warn("[INIT_TRACE] 1. Enter nano_sock_setdb...");
#ifdef NNG_SUPP_SQLITE
    // Only if NNG_SUPP_SQLITE macro is defined, the following code will be compiled
    log_warn("[INIT_TRACE] 2. NNG_SUPP_SQLITE is DEFINED...");
    if (s->conf->sqlite.enable) {
         nni_qos_db_init_sqlite(...); // Execute real initialization
    }
#endif
log_warn("[INIT_TRACE] 3. CHECK CONFIG...");

```

* **Actual Logs**:

> `2026-02-14 ... [INIT_TRACE] 1. Enter nano_sock_setdb. ...`
> `2026-02-14 ... [INIT_TRACE] 3. CHECK CONFIG: s->conf->sqlite.enable is 1`

* **Conclusion**: The log is missing `[INIT_TRACE] 2` and related content. This indicates that during the compilation phase, the `NNG_SUPP_SQLITE` macro was **not defined**. Therefore, the database initialization code wrapped by `#ifdef` was stripped during the preprocessing stage, causing `s->sqlite_db` to maintain the default value (i.e., `NULL`) from the structure allocation.

**2. Propagation: Conflict between Configuration and Runtime Capability (`Conf` vs `Pointer`)**

Although the binary file did not include SQLite support at compile time, the runtime configuration file enabled the relevant option:

> `[INIT_TRACE] 3. CHECK CONFIG: s->conf->sqlite.enable is 1 (1=True)`

This led to an inconsistent logical state:

* **Configuration Flag (`enable`)** is **True**.
* **Actual Object Pointer (`pointer`)** is **NULL**.

Subsequent code logic (such as `nano_pipe_init`) judged solely based on the `enable == 1` flag, mistakenly assuming SQLite was available, and thus **skipped** the default fallback initialization logic based on memory Hashmap. This directly resulted in `pipe->nano_qos_db` pointing neither to an SQLite instance nor to a Hashmap instance, ultimately being assigned `NULL`.

**3. Trigger: Leak Caused by Missing Resource Management (`nni_qos_db_set`)**

When a QoS message with an incremented reference count (Clone 2) enters the persistence function, the issue is triggered.

* **Code Logic**:

```c
void nni_qos_db_set(..., void *db, ..., nng_msg *msg) {
    // ... Print Trace 1 ...
    if (db == NULL) {
        log_warn("[LEAK_TRACE] 2 Enter ... db=(nil) ...");
        // [Logic Defect]
        // Returns directly at this point.
        // It fails to execute the store operation (because db is null)
        // And also fails to release the passed-in msg pointer (resource leak)
        return; 
    }
    // ...
}

```

* **Actual Logs**:

> `nni_qos_db_set: [LEAK_TRACE] 1 Enter ... db=(nil) ...`
> `nni_qos_db_set: [LEAK_TRACE] 2 Enter ... db=(nil) ...`

Here, `db` being `NULL` triggered the function's **Early Return**. At this moment, the passed-in `msg` object (RefCount=3) lost its last opportunity to be managed. After the function exits, no code is responsible for executing the `free` operation on it, causing the memory to be unrecoverable.

**Summary**
The causal chain of the leak caused by the `db` pointer being `NULL` is as follows:

1. **Compilation Level**: `NNG_SUPP_SQLITE` macro undefined, causing initialization code block not to be compiled.
2. **Configuration Level**: `sqlite.enable` enabled, misleading subsequent logic to skip the backup Hashmap initialization.
3. **Execution Level**: `nni_qos_db_set` function lacks defensive programming; it directly discards the `msg` pointer holding the reference count when `db` is empty, without executing necessary resource release.

## IV. Anatomy of the Leak: Resource Leak Caused by Missing DB

### 4.1 Leak Occurrence Point: Missing Resource Management in `nni_qos_db_set`

This is the **fundamental location** where the memory leak occurs.

* **Scenario Description**:
In the `nmq_pipe_send_start_v4` function, to implement the QoS retransmission mechanism, the system performed a **Clone 2** operation (reference count +1) and passed the message pointer `msg` with the increased reference to the `nni_qos_db_set` function. According to the design contract, `nni_qos_db_set` should take over ownership of this reference (i.e., be responsible for storing the message or releasing the message if storage is not possible).
* **Defective Logic**:
```c
void nni_qos_db_set(bool is_sqlite, void *db, uint32_t pipe_id, uint16_t packet_id, nng_msg *msg)
{
    // ... [LEAK_TRACE] 1 ...

    // [Critical Defect]
    if (db == NULL) {
        log_warn("[LEAK_TRACE] 2 Enter ... db=(nil) ...");

        // !!!! Vulnerability Trigger Point !!!!
        // The function detects that the database pointer is uninitialized and executes an "Early Return".
        // At this point, the function holds a message pointer with RefCount=3 but performs no cleanup operations.
        // It neither stores the message in the database nor calls nni_msg_free(msg) to release the currently held reference.
        return;
    }

    // ... Subsequent normal storage logic is skipped ...
}

```


* **Consequence Analysis**:
After the function executes the silent return, the `msg` pointer is lost in the current stack frame. The memory block corresponding to the reference count (Ref=3) generated by **Clone 2** remains in an allocated state, but since all pointers pointing to it are lost, the program can no longer access or release this memory block subsequently, leading to a memory leak.

---

### 4.2 Failure of the Original Third Free: Retrieval Failure in `nni_qos_db_get`

When the server receives the `PUBACK` confirmation packet sent back by the client, the program theoretically releases the memory here. However, due to the invalid database pointer and the loss of the memory address, this path also cannot take effect.

* **Scenario Description**:
In `tcptran_pipe_recv_cb`, the Broker receives `PUBACK`. Logically, the Broker needs to retrieve the cached message copy and release (Free) it.
* **Defective Logic**:
```c
// In the logic for handling CMD_PUBACK:

// Attempt to lookup the corresponding QoS message from the database
// Since the db pointer is NULL, nni_qos_db_get will definitely return NULL
if ((qos_msg = nni_qos_db_get(..., p->npipe->nano_qos_db, ..., ackid)) != NULL) {

    // [Unreachable Code]
    // Only if the query is successful will the remove logic be executed and message memory released
    nni_qos_db_remove_msg(..., qos_msg); // Internally contains nni_msg_free

} else {
    // [Actual Execution Path]
    // Because db is NULL, lookup fails.
    // System determines "message does not exist", only prints a warning log, cannot execute memory release operation.
    log_warn("ACK failed! qos msg %d not found!", ackid);
}

```


* **Consequence Analysis**:
Because the message pointer failed to be successfully stored in the data structure (and was not released) during the "Storage Phase", it naturally cannot be retrieved during the "Acknowledgement Phase". The program flow cannot obtain the pointer to the message object, and therefore cannot execute the release operation.

### Summary

* **Storage Phase Failure**: `nni_qos_db_set` returns directly when encountering a `NULL` pointer, **failing to fulfill the resource release responsibility** (neither stored nor released).
* **Retrieval Phase Failure**: `nni_qos_db_get` cannot retrieve the target object when encountering a `NULL` pointer, leading to the inability to perform post-cleanup.

The combined effect of these two factors prevents the reference count increment from Clone 2 from being balanced, causing the memory block to persist indefinitely within the process lifecycle and resulting in a memory leak.

## V. Comparison: Normal vs. Abnormal Scenarios

### 5.1 Normal Case A: Using Default Memory Mode (Hashmap)

**Configuration**: `sqlite.enable = false`
**Result**: **No Leak**

* **Initialization Phase (`nano_pipe_init`)**:
* The function checks that `sqlite.enable` is false.
* **Action**: Executes the `else` branch, calling `nni_qos_db_init_id_hash`.
* **State**: The `db` pointer is initialized to a valid Hashmap structure address.


* **Storage Phase (`nni_qos_db_set`)**:
* `db` is not empty.
* **Action**: Message is successfully inserted into the Hashmap.
* **Reference**: The Hashmap holds the reference to the message (Clone 2).


* **Cleanup Phase (Receiving PUBACK)**:
* `nni_qos_db_get` finds the message in the Hashmap.
* **Action**: Calls `nni_msg_free`.
* **Outcome**: Reference count drops to zero, memory is reclaimed.



### 5.2 Normal Case B: Correctly Enabling SQLite Persistence

**Configuration**: `sqlite.enable = true`
**Compilation**: **Includes** `-DNNG_SUPP_SQLITE`
**Result**: **No Leak**

* **Initialization Phase (`nano_sock_setdb`)**:
* The `#ifdef NNG_SUPP_SQLITE` block **exists**.
* **Action**: Executes `nni_qos_db_init_sqlite`.
* **State**: `s->sqlite_db` is initialized to a valid SQLite context address.


* **Storage Phase (`nni_qos_db_set`)**:
* `db` is not empty.
* **Action**: Calls `nni_mqtt_qos_db_set` to serialize and store the message to disk.
* **Critical Action**: Since it is persisted, the function **actively executes** `nni_msg_free(msg)` (as shown in code instrumentation).
* **Outcome**: The reference in memory is consumed in time, and data is safely written to disk.



### 5.3 Abnormal Case C: Vulnerability Outbreak (Configuration Enabled + Missing Compilation)

**Configuration**: `sqlite.enable = true`
**Compilation**: **Does not include** `-DNNG_SUPP_SQLITE` (The scenario analyzed)
**Result**: **Severe Memory Leak**

* **Initialization Phase (`nano_sock_setdb` & `nano_pipe_init`)**:
* **Fatal Divergence**:
* `nano_sock_setdb`: Due to **missing macro**, skips SQLite initialization code -> `s->sqlite_db` remains **NULL**.
* `nano_pipe_init`: Due to **enabled configuration** (`enable=true`), mistakenly assumes SQLite is ready, **skips** Hashmap initialization.


* **State**: `pipe->nano_qos_db` is ultimately assigned **NULL**.


* **Storage Phase (`nni_qos_db_set`)**:
* **Black Hole Effect**: Function entry check finds `db == NULL`.
* **Action**: Triggers defensive `return`.
* **Consequences**:
1. Message not stored in Hashmap (not initialized).
2. Message not stored in SQLite (not compiled).
3. **Most Critically**: No one calls `nni_msg_free(msg)`.




* **Cleanup Phase (Receiving PUBACK)**:
* **Cleanup Failure**: `nni_qos_db_get` finds `db` is empty, returns NULL directly.
* **Outcome**: The reference count generated by **Clone 2** (Ref=1) becomes an orphan, occupying memory forever.



### 5.4 Summary Comparison Table

| Scenario | Compilation Option (Macro) | Configuration (Config) | DB Pointer State | Storage Action | Release Action (Free 3) | Result |
| --- | --- | --- | --- | --- | --- | --- |
| **Normal A** | Any | `False` | **Valid (Hashmap)** | Stored in Memory Table | Released after ACK | ✅ Safe |
| **Normal B** | **Present** | `True` | **Valid (SQLite)** | Stored to Disk | Released immediately after storage | ✅ Safe |
| **Abnormal C** | **Absent** | `True` | **Invalid (NULL)** | **Directly Discarded** | **Never Executed** | ❌ **Leak** |

## VI. Security Impact and Conclusion

* **Classification**: CWE-772 (Missing Release of Resource after Effective Lifetime) / CWE-400 (Uncontrolled Resource Exhaustion).
* **Impact**: In resource-constrained IoT edge computing nodes, an attacker (or normal high-concurrency traffic) only needs to establish a standard connection and send QoS messages to trigger silent memory consumption, eventually leading to Out-Of-Memory (OOM) and complete Denial of Service (Silent DoS) of the system.

**Recommendations:**
1. **Fail Fast (Startup Check)**: Add validation logic during the system startup phase (`nano_sock_setdb` or `main` function) to ensure SQLite is running correctly. If `conf->sqlite.enable == true` is detected but the `NNG_SUPP_SQLITE` macro is undefined or SQLite is abnormal, the system should either exit with an error or forcibly set `enable` to `false` and print a warning.
2. **Resource Safety (Fail-Safe)**: Add resource release logic in the Early Return branch of the `nni_qos_db_set` function. If `db == NULL`, `nni_msg_free(msg)` must be called to balance the reference count and prevent memory leaks.