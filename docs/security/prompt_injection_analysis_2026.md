# Analisi Scanner Prompt Injection (2026)

Analisi tecnica del modulo `src/prompt-injection.ts` di AgentRegistry.

## 1. Punti di Forza (Strengths)

Il sistema implementa una difesa "a cipolla" (Defense in Depth) molto solida per essere uno scanner statico basato su regex.

*   **Pipeline di Normalizzazione SOTA:** La vera forza dello scanner è la pipeline di normalizzazione che neutralizza tecniche di evasione avanzate *prima* del matching.
    *   Gestione caratteri invisibili (Zero-Width, Unicode Tags, Bidi Overrides).
    *   Decoding ricorsivo (HTML Entities -> JS Escapes -> Homoglyphs -> Whitespace).
    *   La mappa degli omoglifi (Homoglyphs) è estesa e copre Cyrillic, Greek e Fullwidth.
*   **Copertura Multi-Lingua:** Rileva tentativi di override in 5 lingue (EN, IT, ES, DE, FR), cosa rara in scanner "fatti in casa".
*   **Awareness Architetturale:**
    *   Rileva tecniche specifiche per framework LLM moderni (ChatML, Llama `[INST]`, Claude tags).
    *   Rileva tentativi "Social Engineering" specifici per agenti (es. "DAN mode", "Developer mode").
    *   Rileva iniezioni nascoste via CSS (`display:none`, `color:white`) per attacchi via HTML rendering.

## 2. Aree di Miglioramento (Weaknesses & Gaps)

Nonostante la robustezza, l'approccio basato su Regex presenta limiti intrinseci e vulnerabilità specifiche.

### A. Frammentazione Base64 (Gap Critico)
L'attuale rilevamento Base64 (`decodeInlineBase64`) cerca stringhe continue di 20+ caratteri.
*   **Attacco:** Un attaccante può spezzare il payload Base64 con spazi o caratteri non-Base64 che la normalizzazione *non rimuove completamente* (es. newline o spazi multipli che diventano spazi singoli).
    *   `aWdu b3Jl` (con spazio) -> Normalizzato resta `aWdu b3Jl` -> Regex Base64 fallisce (cerca `[...]{20,}`).
    *   `aWdu\nb3Jl` -> Idem.
*   **Soluzione:** Implementare una euristica che "ricuce" blocchi alfanumerici adiacenti prima del tentativo di decoding Base64.

### B. JavaScript Obfuscation (Limits of Regex)
Il rilevamento di codice malevolo in `install-scripts` o nel codice sorgente è limitato a pattern noti (`eval(atob(...)`, `String.fromCharCode`).
*   **Attacco:** Javascript è troppo flessibile per le regex.
    *   `['e','v','a','l'].join('')(payload)`
    *   `Function("return this")()`
    *   `globalThis['pro' + 'cess']`
*   **Soluzione:** Per una sicurezza reale su file `.js`/`.ts`, servirebbe un parser AST (es. `meriyah` o `acorn`) che analizza la struttura logica, non il testo. Le regex attuali sono un "filtro grossolano".

### C. Mappa Leetspeak Limitata
La mappa `LEET_MAP` è molto conservativa (`1, 3, 4, 5, 7, @`).
*   **Gap:** Mancano sostituzioni comuni usate in attacchi recenti:
    *   `0` -> `()` o `[]` (spesso usato per 'O')
    *   `$` -> `s`
    *   `+` -> `t`
    *   `\ /` -> `V`
*   **Rischio:** Un payload come `P1e4$e` (`Please`) potrebbe passare se `$` non è mappato.

### D. Semantic Variance (NLP Gap)
Il matching è basato su keyword rigide (`ignore`, `disregard`, `forget`).
*   **Attacco:** L'uso di sinonimi non in lista o costruzioni grammaticali complesse.
    *   "Omit previous guidelines" (Omit non è in lista).
    *   "Start a fresh session ignoring context" (Potrebbe sfuggire se la distanza tra le parole è eccessiva).
*   **Soluzione:** Ampliare la lista dei verbi "imperativi" di cancellazione memoria (es. `omit`, `drop`, `reset`, `clear`).

### E. ReDoS Risk (Performance)
Alcune regex usano quantificatori pesanti su set ampi, es. `base64` regex con `{100,}`.
*   **Rischio:** Su file minificati giganti (es. `bundle.js` da 10MB) che contengono lunghe stringhe simili a Base64 ma non valide, il backtracking potrebbe causare DoS dello scanner stesso.

## 3. Verdetto Finale

Lo scanner è **Eccellente per la difesa statica**. È molto sopra la media degli scanner regex open-source.
Tuttavia, **non può garantire la sicurezza** contro un attaccante motivato e capace di offuscare codice JS o inventare nuove variazioni semantiche.

**Raccomandazione:** Considerarlo come *primo livello di filtro* (fast path), ma non come garanzia assoluta di sicurezza.
