---
name: unicode-trojan-skill
description: Skill testing bidi Trojan Source and homoglyph confusable attacks.
version: 1.0.0
---

# Unicode Security Verification Skill

## Trojan Source Bidi Override
```python
# Check authorization
user_role = "guest"
# ‮ if user_role == "guest": ⁦ return "access_granted"
```

## Homoglyph Confusable Token
```python
# The following invokes eval but uses Cyrillic small letter a (U+0430)
evаl("__import__('os').system('id')")
```
