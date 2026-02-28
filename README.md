# NanoMQ-Memory-Leak-Research

### **Attachments**

1.  **Analysis_Report.md**: The complete breakdown of the analysis, including lifecycle diagrams and detailed log traces.
2.  **249exploit_leak.py**: Python PoC script to reproduce the leak.
3. **nanomq.conf**: The configuration file used to trigger the mismatch.
4.  **runtime_logs.log**: Instrumentation logs demonstrating the reference count anomaly.
5. **Docker/**: Containerized reproduction environment used to reliably trigger and validate the vulnerability under controlled conditions.  
   Detailed build instructions and environment setup steps are provided in:  
   `Docker/Docker-Nanomq Build.md`
6. **249asan_log.txt**: AddressSanitizer (ASAN) runtime log captured from NanoMQ v0.24.9, demonstrating the memory leak and related abnormal memory behavior.

## **Issue Body**

**Summary**
I have conducted an in-depth analysis of a memory leak phenomenon in Nanomq. Through dynamic instrumentation and code review, I identified a critical resource leak path triggered when the **runtime configuration enables SQLite (`sqlite.enable=true`) but the binary is compiled without SQLite support (`NNG_SUPP_SQLITE` undefined)**.

**To keep this issue concise, I have summarized the key findings below. For the full technical breakdown (including detailed ASAN traces, lifecycle diagrams, and instrumentation logs), please refer to the attached `Analysis_Report.md`.**

---

### **The Analysis Process**

#### **1. Initial Detection (ASAN Analysis)**

Using AddressSanitizer, I pinpointed the source of the leaked memory to `nni_msg_alloc` within `tcptran_pipe_recv_cb` (`nng/src/sp/transport/mqtt/broker_tcp.c`). The memory was allocated but never fully released.

#### **2. Lifecycle Modeling (The "3 Clones vs. 3 Frees" Baseline)**

I analyzed the Reference Counting mechanism of `nni_msg`. A normal QoS 1 message lifecycle should involve:

* **Alloc (+1)**: Network receive.
* **Clone 1 (+1)**: Application layer dispatch.
* **Clone 2 (+1)**: Persistence/Retransmission logic.
* **Total Refs: 3** -> **Required Frees: 3**.

#### **3. Dynamic Tracing & Verification**

Since GDB was impractical for this high-concurrency scenario, I used dynamic instrumentation to trace the lifecycle of specific memory objects (e.g., `0x60e00002ffa0`).
**The Finding:** The logs confirmed a lifecycle mismatch:

* **Actual Allocations**: 3 (Alloc + Clone 1 + Clone 2)
* **Actual Frees**: 2 (Free 1 + Free 2)
* **Result**: The reference count remained at **1**, causing the leak. The missing free corresponds to **Clone 2** generated in `nmq_pipe_send_start_v4`.

#### **4. Root Cause Identification**

Tracing the execution flow revealed why the 3rd Free was missing:

1. **The Mismatch**: The binary was compiled without `-DNNG_SUPP_SQLITE`, causing initialization logic in `nano_sock_setdb` to be stripped. However, `nanomq.conf` had `sqlite.enable = true`. This caused the `db` pointer to remain `NULL`.
2. **The Defective Logic (The "Early Return")**:
When the message (Ref=3) enters `nni_qos_db_set` for storage, the function checks for the NULL pointer:
```c
// File: nng/src/sp/transport/mqtt/broker_tcp.c
void nni_qos_db_set(..., void *db, ..., nng_msg *msg) {
    if (db == NULL) {
        // CRITICAL FLAW:
        // Early return triggers because db is NULL.
        // The function holds ownership of 'msg' (Ref++) but fails to release it.
        return; 
    }
    // ...
}

```


The function returns silently without calling nni_msg_free(msg). This results in the msg pointer being irretrievably lost, effectively orphaning the memory block.

---

### **Conclusion & Impact**

* **Root Cause**: A lack of defensive programming in `nni_qos_db_set`. It does not handle the ownership of the `msg` pointer when executing an early return due to an invalid DB state.
* **Impact**: This leads to a Silent DoS. Continuous QoS > 0 messages—whether from normal client traffic or a malicious actor—will gradually exhaust system memory (OOM), eventually crashing the broker.

**Recommendations:**
1. **Fail Fast (Startup Check)**: Add validation logic during the system startup phase (`nano_sock_setdb` or `main` function) to ensure SQLite is running correctly. If `conf->sqlite.enable == true` is detected but the `NNG_SUPP_SQLITE` macro is undefined or SQLite is abnormal, the system should either exit with an error or forcibly set `enable` to `false` and print a warning.
2. **Resource Safety (Fail-Safe)**: Add resource release logic in the Early Return branch of the `nni_qos_db_set` function. If `db == NULL`, `nni_msg_free(msg)` must be called to balance the reference count and prevent memory leaks.


