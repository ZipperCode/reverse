High-performance, structured Dalvik/ART bytecode search engine powered by LuckyPray/DexKit (C++20 core and JNI bridge). Queries classes, methods, and fields matching complex constraints (string constants, types, signatures, annotations, call graphs, and cross-references) directly against APK archives or raw DEX files.

Input scope:
- Android `.apk` files
- Raw `.dex` files (unlike droidasc, DexKit directly parses raw `.dex` and multi-DEX files)
- `.jar` or `.zip` archives containing `classes*.dex`

Operations (`type` / `action`):
- `class`: Search for classes matching class name pattern, superclass, interfaces, modifiers, annotations, or string literals used anywhere in the class.
- `method`: Search for methods matching declaring class, method name, return type, parameter types, modifiers, annotations, used strings, used numbers, or invoked calls.
- `field`: Search for fields matching declaring class, field name, field type, modifiers, or annotations.
- `callers`: Method cross-reference search: find all methods that call the specified `target_method` descriptor (e.g. `Lcom/example/Auth;->verifyToken(Ljava/lang/String;)Z`).
- `callees` (or `invokes`): Call-graph search: find all methods called by the specified `target_method` descriptor.
- `field_uses` (or `field_refs`): Field cross-reference search: find all methods that read (iget/sget) or write (iput/sput) the specified `target_field` descriptor (e.g. `Lcom/example/Auth;->token:Ljava/lang/String;`).
- `batch_strings`: Batch search across multiple groups of string literal constants in parallel, returning matches grouped by dictionary key.
- `info`: Quick inspection of parsed DEX count, engine version, and status.

Features & Handoff:
- Every returned method and class includes stable smali descriptors (e.g. `Lcom/example/Gate;->check(I)Z`), clean Java signatures, and ready-to-use Frida hook snippets for instant dynamic tracing.
- JADX navigation hints for rapid code browsing.
- Target SHA-256 provenance hash.
- Bounded pagination with `limit` (default 50) and `offset`.

When `dexkit` engine components are not installed, returns structured dependency notice with setup command `reverse setup reverse dexkit --execute` and active fallbacks (`droidasc`, `dex_patch`).

<examples>
```
// Search for methods using sensitive string literals
dex_search(target: "app.apk", type: "method", using_strings: ["AES/CBC/PKCS5Padding", "SecretKeySpec"])

// Search for classes extending Activity and implementing View.OnClickListener
dex_search(target: "app.apk", type: "class", super_class: "android.app.Activity", className: "com.example")

// Find all callers of a target authentication method
dex_search(target: "classes.dex", type: "callers", method: "Lcom/example/auth/TokenValidator;->isValid(Ljava/lang/String;)Z")

// Find all methods that read or write a sensitive encryption key field
dex_search(target: "app.apk", type: "field_uses", field: "Lcom/example/crypto/KeyStore;->masterKey:Ljava/lang/String;")

// Search methods matching name and return type with specific parameter types
dex_search(target: "app.apk", type: "method", name: "decrypt", return_type: "byte[]", param_types: ["byte[]", "java.lang.String"])

// Batch search for methods matching multiple feature keyword groups
dex_search(target: "app.apk", type: "batch_strings", groups: { "license": ["licensed", "expired"], "network": ["https://api.", "Authorization"] })
```
</examples>
