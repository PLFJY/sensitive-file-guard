# Linux Acceptance Rules

## 1. Evidence hierarchy

从强到弱：

1. **LIVE adversarial acceptance**
   - synthetic fixture
   - real kernel mechanism
   - Guard-side attribution
2. Privileged integration test
3. Unit/integration test
4. Static code inspection
5. Commit message / comment

低层证据不能替代高层 gate。

---

## 2. PREVENTED oracle

一个攻击场景标 `PREVENTED`，至少满足：

```text
A. Guard OFF / policy OFF baseline 能证明 attack primitive 原本可成功
   或明确证明 OS-default policy 不会独立造成同样 denial

B. Guard ON 后 kernel operation 被拒绝

C. Guard 记录 exact target / requester / event kind 的 deny attribution

D. synthetic secret canary 没有恢复

E. harness 自己没有因为权限、路径、Yama、SELinux/AppArmor 等原因伪造 denial
```

如果 A 做不到：

```text
Guard causality NOT VERIFIED
```

不得写 PREVENTED。

---

## 3. Root test 规范

- build as ordinary user；
- root 只执行 kernel-dependent harness；
- root harness 使用 synthetic temp directories；
- root harness 不读取用户真实 `$HOME` 下的 secrets；
- privilege 默认仅通过 `sudo -n /usr/local/sbin/sfg-test-capsule`；若用户明确
  授权且 capsule 差异阻止最终结论，可对单一已审查 host gate 使用 polkit，且不得
  请求、接收、缓存或管道传递密码；
- `/stage` 只读，破坏性 fixture/evidence 只在 `/testfs`；
- 不得使用 interactive sudo、`sudo -S`、密码缓存；`pkexec` 仅限用户明确授权的
  单一已审查 host gate，且不得请求、接收或传递密码；
- root test exit code 非 0 时必须输出 stage + evidence dir。

每个 script 统一：

```text
=== <NAME> SUMMARY pass=N fail=N blocked=N ===
```

`fail > 0` 必须 exit 1；无法执行的 mandatory gate 必须 exit 2；只有
`fail = 0 && blocked = 0` 才能 exit 0。

---

## 4. Performance gate

先在 LFH0 锁定 baseline。

默认 regression budget（可依据真实 LFH0 数据调整并写入 report）：

```text
ordinary unprotected open p95:
  <= baseline * 1.20

ordinary unprotected throughput:
  >= baseline * 0.85

fanotify_overflows:
  0

classifier_failures:
  0
```

禁止通过降低安全覆盖换 benchmark。

---

## 5. Browser compatibility gate

只使用：

```text
real installed browser executable
+
disposable synthetic profile
```

浏览器：

```text
Firefox
Chromium/Chrome（至少一种 Chromium 主实现）
Zen（安装存在时）
```

测试：

```text
startup
normal browsing against local/harmless content
new tab
profile DB replacement
Cookies access
Login Data / logins.json
Sessions/sessionstore
Local Storage
IndexedDB
extension activity if fixture exists
restart
```

要求：

```text
0 unexplained protected DENY
0 classifier failure
0 fanotify overflow
0 continuity loss
unauthorized synthetic reader remains denied
```

---

## 6. Final File Shield gate

`LINUX_FILE_SHIELD_FREEZE` 只有以下都满足才 COMPLETE：

- strict-filesystem 是唯一 formal accepted mode；
- missing/legacy config 不会 silent downgrade；
- PID reuse / executable replacement identity tests pass；
- accepted kernel 上 pidfd path pass；
- dynamic object rename/inode-reuse story 有 live evidence；
- symlink/hardlink/rename/WAL/SHM adversarial pass；
- migration exact authority semantics pass；
- SSH exact-reader/load semantics pass；
- continuity state 对 overflow/restart 诚实；
- root/live tests pass；
- native disposable browser stress pass；
- performance gate pass；
- docs truthfulness pass；
- full workspace quality gate pass。

---

## 7. Final Process Shield gate

`LINUX_PROCESS_SHIELD_FREEZE` 只有以下都满足才 COMPLETE：

- BPF LSM capability probe truthfully separates supported/unsupported；
- unsupported Process Shield 不影响 File Shield；
- synthetic baseline proves attack primitive succeeds without Guard；
- Guard ON:
  - ptrace control denied
  - `process_vm_readv` denied
  - `process_vm_writev` denied
  - `/proc/<pid>/mem` denied where hook semantics cover it
- exact Guard attribution exists；
- memory canary recovery = 0；
- Browser SecretAuthority matrix finished；
- only necessary roles are shielded；
- normal browser use has no unexplained deny/false Compromised equivalent；
- File Shield remains green after Process Shield enabled。
