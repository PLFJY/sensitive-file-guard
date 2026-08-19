# LPS3 — Authority Admission + Process Shield Policy

根据 LPS2 evidence实现最窄 admission。

原则：

```text
BrowserIdentity != SecretAuthority
Browser process tree != SecretAuthority
```

优先：

```text
Main at exec/lifecycle establishment
```

固定 secret-capable helper若确实必要：

```text
exact role + exact instance
```

不要：

```text
all helpers
same UID
same BrowserId
same Team/package family equivalent
```

BPF LSM policy：

```text
target not protected → leave normal kernel policy
target protected + explicit safe relationship → allow
target protected + unknown same-user requester → deny
root/kernel attacker → outside guarantee
```

输出：

```text
reports/linux/lps3-policy.md
```
