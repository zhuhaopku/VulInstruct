# Threat Modeling Analysis Prompt

def generate_threat_model_prompt(repository, commit_message, cve_description, cwe_type, code_context, vuln, fixed):
    """Generate threat modeling prompt"""
    
    template = """
A structured threat modeling analysis process where security experts conduct systematic security analysis based on provided information. The expert must:

## 1. **Understand Code Context** (within `<understand>` tags)
Thoroughly analyze and describe the system context without revealing the vulnerability itself:

### System Identification
- **What system**: Clearly identify the software system, library, or application
- **Domain/Subsystem**: Specify the particular domain or subsystem where the code operates
- **Module/Component**: Identify the specific module, component, or functional unit

### Functional Analysis  
- **Core functionality**: Describe what this system/module is designed to do in detail: 1. 2. 3


## 2. **Security Domain Classification** (within `<classification>` tags)
Classify vulnerabilities according to 10 core security domains:

### Core Security Domains:
1. **MEM**: Memory Safety  [Buffer errors (`BOUND`, `BUF`), pointer issues (`PTR`), use-after-free (`LIFECYCLE`), allocation problems (`ALLOC`, `MM`), uninitialized use (`INIT`), address handling (`ADDR`, `VMA`).]
2. **STATE**: State Management [Inconsistent states (`STATE`, `CONSIST`), object lifecycle (`LIFECYCLE`, `REFCNT`), concurrency issues (`SYNC`, `LOCK`, `CONCURRENT`, `ATOMIC`), and initialization (`INIT`).]
3. **INPUT**: Input Validation [Parsing logic (`PARSE`, `FORMAT`), data validation (`VALID`, `VERIFY`), type checking (`TYPE`), encoding (`ENCODING`), and checking data properties (`LEN`, `OFFSET`, `TAG`).]
4. **LOGIC**: Program Logic [Arithmetic errors (`INT`, `ARITH`), type confusion (`TYPECHECK`), logical mistakes (`LOGIC`), and exception/error handling (`ERROR`, `EXCEPT`, `FAIL`).]
5. **SEC**: Security Features [Authentication (`AUTH`), cryptography (`CRYPTO`), permissions (`PERM`, `PRIV`, `ACL`), and policy enforcement (`POLICY`, `SANDBOX`).]
6. **IO**: I/O Interaction [Filesystem operations (`FS`, `FILE`, `PATH`), networking (`NET`, `HTTP`, `DNS`), device interaction (`IO`, `USB`, `DMA`), and resource management (`RESOURCE`)]
7. **CONF**: Configuration Environment [Configuration parsing (`CONFIG`), environmental variables (`ENV`), default settings (`DEFAULT`), and platform architecture (`PLATFORM`, `ARCH`).]
8. **TIMING**: Timing & Concurrency [Race conditions (CONCURRENT, RACE), synchronization issues (SYNC, LOCK, ATOMIC, THREAD), time-of-check-to-time-of-use (TOCTOU) bugs, and timing attacks (TIMING, TIMEOUT).]
9. **PROTOCOL**: Protocol Communication [message parsing/formatting errors (MSG, HDR, FORMAT), session handling (SESSION), and protocol-level security issues like replay attacks (REPLAY).]
10. **HARDWARE**: Hardware & Low-level [Low-level interfaces (IOCTL, MSR, DMA), architectural specifics (ARCH, VMX), hardware state management (REG, CACHE), and side-channel attacks (SIDE).]


### Classification Requirements:
- Determine **Primary Classification**: Select the core domain that best describes the root cause of the vulnerability
- Specify **Sub-domain**: Specific category under primary classification (e.g., STATE.CONSISTENCY, MEM.BUFFER)
- Add **Contextual Tags**: Other relevant but non-primary security domain tags

### Classification Example:
```
Primary Classification: STATE.CONSISTENCY
Contextual Tags: [INPUT.PARSE, IO.NETW, CONF.OPTIONS, SEC.XXE]
Description: XML parser incorrectly loads external entities in non-validating mode, program behavior inconsistent with internal state
```

## 3. **Security Specification** (within `<spec>` tags)
Security Specification is a crucial concept that helps us understand how vulnerable code violates the constraint rules of the developer's original intention and how patched code implements the fix. 

### Security Specification Requirements:
- Each security Specification includes unique identifier (`HS-<DOMAIN>-<NNN>` in classification results)
- Use "positive action" structure
- For relatively simple vulnerabilities, limit to 2 or fewer specifications and provide the most essential ones
- Ensure traceability to specific vulnerability description or repair commit
- Focus on the underlying semantic knowledge and domain rules - such as protocol constraints, business logic invariants, or fundamental program semantics.


We can reason through this in the following ways:
### Reasoning Pattern Examples:

#### 1. Reverse Reasoning Pattern
**State Consistency Specification**:
- Vulnerability phenomenon → "XML parser loads external entities in non-validating mode"
- Positive requirement → "Parser behavior must remain consistent with configuration state"
- Security Specification: HS-STATE-001: Parser operation privileges must be strictly constrained by validation mode state

#### 2. Causal Analysis Pattern
**Pointer Lifecycle Specification**:
- Logic issue → "Freed pointer not nullified causing dangling pointer"
- Root requirement → "Pointer release operations must atomically complete state cleanup"
- Security Specification: HS-MEM-002: Pointer release must include immediate nullification forming atomic unit

#### 3. Domain Mapping Pattern
**Protocol Boundary Specification**:
- Domain concept → "HTTP message integrity boundary"
- Security property → "Content-Length must precisely match actual data"
- Security Specification: HS-PROTOCOL-003: Protocol implementation must enforce byte-level consistency validation between message headers and body

#### 4. Defensive Design Pattern
**Input Normalization Specification**:
- Vulnerability source → "Non-canonical input bypasses validation logic"
- Design principle → "All external input must undergo standardization processing"
- Security Specification: HS-INPUT-004: Input processing pipeline must implement pre-parse normalization and boundary checking

#### 5. Temporal Security Pattern
**Concurrent Access Specification**:
- Failure mode → "Race condition causes state inconsistency"
- Protection mechanism → "Shared resource access must guarantee atomicity"
- Security Specification: HS-TIMING-005: Shared state modifications must ensure operation atomicity through synchronization primitives

---

## 📋 Example

### Input Information
**Repository**: ksmbd
**Commit Message**: ksmbd: Fix dangling pointer in krb_authenticate
**CVE Description**: In the Linux kernel, the following vulnerability has been resolved: ksmbd: Fix dangling pointer in krb_authenticate. krb_authenticate frees sess->user and does not set the pointer to NULL. It calls ksmbd_krb5_authenticate to reinitialise sess->user but that function may return without doing so. If that happens then smb2_sess_setup, which calls krb_authenticate, will be accessing free'd memory when it later uses sess->user.
**CWE Type**: CWE-416 (Use After Free)
**Code Diff**:
```diff
 if (prev_sess_id && prev_sess_id != sess->id)
     destroy_previous_session(conn, sess->user, prev_sess_id);
 
-if (sess->state == SMB2_SESSION_VALID)
+if (sess->state == SMB2_SESSION_VALID) {{
     ksmbd_free_user(sess->user);
+    sess->user = NULL;
+}}
```

### Expected Output Format:


## understand example:
<understand>
### System Identification
- **What system**: ksmbd - in-kernel SMB server implementation for Linux
- **Domain/Subsystem**: SMB/CIFS network file sharing protocol implementation
- **Module/Component**: 
    Kernel component receives SMB requests, uses netlink IPC to communicate with user-space tools for authentication and RPC handling
  - Kernel component: Accepts SMB connections and handles protocol requests
  - User-space component (ksmbd-tools): Handles RPC calls, authentication processes, and configuration
  - Communication mechanism: Netlink IPC between kernel and user-space components

### Functional Analysis  
- **Core functionality**: Implement SMB/CIFS protocol to provide network file sharing services, allowing clients to access files and resources on the server. More detail: 1. 2. 3. 
</understand>


# example:
<classification>
    <primary>MEM.LIFECYCLE</primary>
    <tags>[STATE.CONSISTENCY, SEC.AUTHENTICATION, PROTOCOL.SMB]</tags>
    <reasoning>The root cause is the failure to manage the lifecycle of a pointer after its memory is freed, leading to a dangling state.</reasoning>
    <keywords>['dangling pointer', 'frees ... and does not set the pointer to NULL', 'accessing free'd memory']</keywords>
    <summary>A memory lifecycle violation where a dangling pointer is used during the SMB authentication process.</summary>
</classification>

<spec>HS-MEM-001: Pointer release operations require atomic cleanup with immediate nullification</spec>
- Reasoning: Dangling pointer vulnerability → freed but not nullified → atomic release-nullification prevents use-after-free

<spec>HS-AUTH-002: Authentication failure handling ensures state consistency and explicit error propagation</spec>
- Reasoning: Authentication reinitialization failure + unchecked returns → combines session state integrity with caller error handling contract

---

## 📋 Current Analysis Target

**Repository**: {repository}
**Commit Message**: {commit_message}
**CVE Description**: {cve_description}
**CWE Type**: {cwe_type}
**Vulnerable Code**:
```c
{vuln}
```
**Solution**:
```c
{fixed}
```
**Code Context**:
```c
{code_context}
```


Please conduct analysis following the above format.
"""
    
    return template.format(
        repository=repository,
        commit_message=commit_message,
        cve_description=cve_description,
        cwe_type=cwe_type,
        vuln=vuln,
        fixed=fixed,
        code_context=code_context
    )


def generate_context_model_prompt(commit_message, cve_description, cwe_type, code_context, vuln, fixed, understand, specification):
    """Generate threat modeling prompt"""
    
    template = """
A structured threat modeling analysis process where security experts conduct systematic security analysis based on provided information.

## Analysis Framework

### 1. System Understanding (provided context)
{understand}

### 2. Security Specifications (provided rules)
{specification}

### 3. System-Level Threat Modeling (within `<model>` tags)
Analyze vulnerability at system design level:
**Trust Boundaries**: Identify where system components transition between trusted/untrusted states
**Attack Surfaces**: Focus on realistic attack vectors that led to this specific vulnerability
**CWE Analysis**: Trace complete vulnerability chain (e.g., initial CWE-X triggers subsequent CWE-Y, where at least one matches: {cwe_type} (annotation in cve detail))



### 4. Code-Level Analysis 

#### Vulnerability Context (within `<vuln>` tags)
Provide a granular, narrative explanation of the vulnerability, following this structure:
1.  **Entry Point & Preconditions**: Describe how the attack is initiated and what system state is required.
2.  **Vulnerable Code Path Analysis**: Provide a step-by-step trace of the execution flow. Name key functions and variables. Pinpoint the exact flawed logic (`The Flaw`) and its immediate result (`Consequence`).
3.  **Specification Violation Mapping**: Explicitly link steps in the code path analysis to the specific `HS-` specifications they violate.
Expected level of detail and format:
<vuln>
  #### 1. Entry Point & Preconditions
  - [Describe how an attacker interacts with the system and what state the system must be in to trigger the vulnerability.]

  #### 2. Vulnerable Code Path Analysis
  - [A numbered, step-by-step trace of the code's execution flow, naming key functions, variables, and logic.]
  - **Step 1**: ...
  - **Step 2**: ...
  - **The Flaw**: **Step N**: [Pinpoint the exact line or logical check that is incorrect.]
  - **Consequence**: [Describe the immediate result of the flaw, e.g., an out-of-bounds write.]

  #### 3. Specification Violation Mapping
  <spec="HS-classification-XXX"> [Violation Point: Explain which step or code snippet in the Vulnerable Code Path Analysis specifically violates this specification.] 
  [Violation Mechanism: Describe how the flawed logic leads to a violation of the specification.] </spec>
</vuln>





#### Fix Implementation (within `<solution>` tags)  
Explain how the patch enforces security specifications:
- Specific code changes and their security impact
- How fixes restore compliance with violated specifications

Provide a detailed explanation template of the code changes to explain fixing:

**Change 1: Bounds Check Correction**
<enforcement spec="HS-classification-XXX">
<location>net/xxx.c, xxx()</location>
<diff> // concise code logic and code change
- [original code]
+ [fixed code] 
</diff>
    <compliance_mechanism>
        [describe how the fix changes.]
    </compliance_mechanism>
</enforcement>




#### example model:
<model>
  <trust_boundaries>
    - **User-Kernel Boundary**: During the `smb2_sess_setup` system call, the kernel processes data from an untrusted user.
    - **Intra-Kernel Function Contract**: The caller `smb2_sess_setup` trusts the callee `krb_authenticate` to leave the shared `sess` object in a consistent and safe state upon return, even after failure. This trust is violated.
  </trust_boundaries>
  <attack_surfaces>
    - **Network Request**: The primary attack surface is a malicious SMB2 SESSION_SETUP request sent over the network.
    - **Error Path Exploitation**: The specific vector is crafting a request that causes the `ksmbd_krb5_authenticate` function to fail, triggering the vulnerable error handling path.
  </attack_surfaces>
  <cwe_analysis>
    The primary vulnerability is **CWE-416 (Use After Free)**. This is enabled by a violation of state management principles, where a pointer's state becomes inconsistent with the state of the memory it references.
  </cwe_analysis>
</model>


#### Execution Flow:
<vuln>
  #### 1. Entry Point & Preconditions
  - **Entry Point**: A privileged user (requiring `CAP_NET_ADMIN`) sends a Netlink message of type `NETLBL_MGMT_ADDDEF` to the kernel to define a new CIPSOv4 Domain of Interpretation (DOI).
  - **Precondition**: The message contains a specially crafted `NLBL_CIPSOV4_A_TAGLST` attribute, which includes the maximum number of tags, `CIPSO_V4_TAG_MAXCNT` (which is 31).

  #### 2. Vulnerable Code Path Analysis(Execution Flow)
  - **Step 1**: The kernel's Netlink subsystem routes the request to the `netlbl_cipsov4_add_common()` function for processing.
  - **Step 2**: Inside this function, a `doi_def` struct is handled. It contains the array `doi_def->tags[]` of size `CIPSO_V4_TAG_MAXCNT`, meaning it has 31 elements with valid indices from 0 to 30.
  - **Step 3**: A loop (`nla_for_each_nested`) iterates through the tag list provided by the attacker in the Netlink message. A counter variable, `iter`, tracks the number of tags processed, starting from 0.
  - **The Flaw**: **Step 4**: At the beginning of each iteration, the code performs a bounds check on the counter:
    ```c
    if (iter > CIPSO_V4_TAG_MAXCNT)
    ```
    This is a classic **off-by-one error**. When `iter` is 31 (which should be an invalid index), the condition `31 > 31` evaluates to **false**, and the check is incorrectly bypassed.
  - **Consequence**: **Step 5**: Because the flawed check passed, the code proceeds to execute `doi_def->tags[iter++] = tag;`. With `iter` equal to 31, this results in a write operation to `doi_def->tags[31]`, an index that is one element past the end of the array's allocated boundary. This causes a small but critical stack buffer overflow.

  #### 3. Specification Violation Mapping

  <spec="HS-MEM-001"> (Array index validation must use inclusive upper bound comparison)**: 
    - **Violation Point**: Bounds check using `iter > CIPSO_V4_TAG_MAXCNT`
    - **Violation Mechanism**: Exclusive comparison allows invalid index 31 </spec>
  <spec="HS-STATE-002"> (Array initialization must guarantee complete coverage)**: 
    - **Violation Point**: Single assignment `doi_def->tags[iter] = CIPSO_V4_TAG_INVALID`
    - **Violation Mechanism**: Only initializes one element after input processing </spec>
</vuln>

#### Code Changes:
**Change 1: Bounds Check Correction**
<enforcement spec="HS-MEM-001">
<location>net/netlabel/netlabel_cipso_v4.c, netlbl_cipsov4_add_common()</location>
<diff>
 	nla_for_each_nested(nla, nla_a, nla_rem) {{
-		if (iter > CIPSO_V4_TAG_MAXCNT)
+		if (iter >= CIPSO_V4_TAG_MAXCNT)
 			return -EINVAL;
 		
 		tag = nla_get_u8(nla);
 		if (tag == CIPSO_V4_TAG_RBITMAP ||
            ... 
 		    tag == CIPSO_V4_TAG_FREEFORM) {{
 			doi_def->tags[iter++] = tag;
 		}} else
 			return -EINVAL;
 	}}
</diff>
    <compliance_mechanism>
        The fix changes the boundary check from exclusive (>) to inclusive (>=) comparison. This ensures that when iter equals CIPSO_V4_TAG_MAXCNT (the first invalid index), the condition evaluates to true and prevents any array access beyond the allocated bounds.
    </compliance_mechanism>
</enforcement>

**Change 2: Complete Array Initialization**
<enforcement spec="HS-STATE-002">
<location>net/netlabel/netlabel_cipso_v4.c, netlbl_cipsov4_add_common() </location>
<diff>
 	nla_for_each_nested(nla, nla_a, nla_rem) {{
    ... 
 	}}
-	doi_def->tags[iter] = CIPSO_V4_TAG_INVALID;
+	while (iter < CIPSO_V4_TAG_MAXCNT)
+		doi_def->tags[iter++] = CIPSO_V4_TAG_INVALID;
</diff>
    <compliance_mechanism>
    The fix replaces single-element initialization with a complete array traversal. The while loop iterates from the current iter position to CIPSO_V4_TAG_MAXCNT, ensuring every remaining array element is explicitly initialized to a known safe value (CIPSO_V4_TAG_INVALID).
    </compliance_mechanism>
</enforcement>


</solution>



## Input Information
- **CVE**: {cve_description}
- **CWE**: {cwe_type}  
- **Commit**: {commit_message}
- **Vulnerable Code**: {vuln}
- **Fixed Code**: {fixed}
- **Code Context**: {code_context}

Please conduct analysis following the above framework.
"""
    
    return template.format(
        understand=understand,
        specification=specification,
        cve_description=cve_description,
        cwe_type=cwe_type,
        commit_message=commit_message,
        vuln=vuln,
        fixed=fixed,
        code_context=code_context
    )













def generate_understand_model_prompt(repository, commit_message, cve_description, cwe_type, code_context, vuln, fixed):
    """Generate threat modeling prompt"""
    
    template = """
A structured threat modeling analysis process where security experts conduct systematic security analysis based on provided information. The expert must:

##  *Understand Code Context** (within `<understand>` tags)
Thoroughly analyze and describe the system context without revealing the vulnerability itself:

### System Identification
- **What system**: Clearly identify the software system, library, or application
- **Domain/Subsystem**: Specify the particular domain or subsystem where the code operates
- **Module/Component**: Identify the specific module, component, or functional unit

### Functional Analysis  
- **Core functionality**: Describe what this system/module is designed to do in detail: 1. 2. 3

---

## 📋 Example

### Input Information
**Repository**: ksmbd
**Commit Message**: ksmbd: Fix dangling pointer in krb_authenticate
**CVE Description**: In the Linux kernel, the following vulnerability has been resolved: ksmbd: Fix dangling pointer in krb_authenticate. krb_authenticate frees sess->user and does not set the pointer to NULL. It calls ksmbd_krb5_authenticate to reinitialise sess->user but that function may return without doing so. If that happens then smb2_sess_setup, which calls krb_authenticate, will be accessing free'd memory when it later uses sess->user.
**CWE Type**: CWE-416 (Use After Free)
**Code Diff**:
```diff
 if (prev_sess_id && prev_sess_id != sess->id)
     destroy_previous_session(conn, sess->user, prev_sess_id);
 
-if (sess->state == SMB2_SESSION_VALID)
+if (sess->state == SMB2_SESSION_VALID) {{
     ksmbd_free_user(sess->user);
+    sess->user = NULL;
+}}
```

### Expected Output Format:


## understand example:
<understand>
### System Identification
- **What system**: ksmbd - in-kernel SMB server implementation for Linux
- **Domain/Subsystem**: SMB/CIFS network file sharing protocol implementation
- **Module/Component**: 
    Kernel component receives SMB requests, uses netlink IPC to communicate with user-space tools for authentication and RPC handling
  - Kernel component: Accepts SMB connections and handles protocol requests
  - User-space component (ksmbd-tools): Handles RPC calls, authentication processes, and configuration
  - Communication mechanism: Netlink IPC between kernel and user-space components

### Functional Analysis  
- **Core functionality**: Implement SMB/CIFS protocol to provide network file sharing services, allowing clients to access files and resources on the server. More detail: 1. 2. 3. 
</understand>

---

## 📋 Current Analysis Target

**Repository**: {repository}
**Commit Message**: {commit_message}
**CVE Description**: {cve_description}
**CWE Type**: {cwe_type}
**Vulnerable Code**:
```c
{vuln}
```
**Solution**:
```c
{fixed}
```
**Code Context**:
```c
{code_context}
```


Please conduct analysis following the above format.
"""
    
    return template.format(
        repository=repository,
        commit_message=commit_message,
        cve_description=cve_description,
        cwe_type=cwe_type,
        vuln=vuln,
        fixed=fixed,
        code_context=code_context
    )

