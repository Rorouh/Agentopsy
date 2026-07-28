# windows.info — perfil del sistema (legible)

Salida cruda: [`01__raw.txt`](01__raw.txt) · tool: `volatility3 2.28.0`, plugin `windows.info`.

| Dato | Valor | Para qué sirve |
|---|---|---|
| **SO** | Windows 7 SP1 **x64** | perfil de análisis |
| **Build** | `7601.24384.amd64fre.win7sp1_ldr_` | versión exacta |
| **Versión NT** | 6.1 (Major/Minor 15.7601) | |
| **Arquitectura** | Is64Bit = True, 1 procesador | |
| **⭐ Hora del volcado** | **2021-03-23 19:24:35 +00:00 (UTC)** | ancla temporal del informe |
| **NtSystemRoot** | `C:\Windows` | |
| **Símbolos** | `ntkrnlmp.pdb` resueltos (bundled) | vol3 opera sin descargar nada |

## Notas

- La `SystemTime` de `windows.info` es **UTC** (viene de `KUSER_SHARED_DATA`). La **zona
  horaria configurada** del equipo aún está por sacar del registro (`registry.timezone` /
  hive `SYSTEM`): es lo que traducirá esta UTC a la hora local del usuario. **Hasta tenerla,
  todas las horas se anotan en UTC.**
- ✅ **Validación del método:** este perfil coincide con el que traía el README de la
  evidencia en el proyecto de origen, que se decidió **no copiar**
  ([a2](../../REGISTRO-DECISIONES.md#a2-evidencia-ram)). El flujo lo re-derivó por su cuenta
  — que es justo la prueba de que el flujo funciona, no un apaño con la respuesta puesta.
