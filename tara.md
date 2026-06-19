# Threat Analysis and Risk Assessment (TARA)

**Standard**: ISO 21434  
**Generated**: 2026-06-19T18:26:05Z  
**Tool**: rust-FuSa 0.2.8  

## Threat Register

| Threat | STRIDE | CWE | Risk | Mitigation | Rule |
|--------|--------|-----|------|------------|------|
| deserialisation of external data — ensure input is size-bounded and validated | T | CWE-502 | MEDIUM | validate structure and field bounds after deserialisation before use | CYBER010 |
| direct slice indexing with a variable — consider .get() for bounds-safe access | T | CWE-125 | MEDIUM | use .get(index) which returns Option instead of panicking on out-of-bounds | CYBER011 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |
| write!( called with non-literal first argument — ensure it is not user-controlled | T | CWE-134 | MEDIUM | use a string literal as the format template; pass dynamic content as arguments | CYBER019 |

## Summary

- Total: 7
- HIGH: 0
- MEDIUM: 7
- LOW: 0
