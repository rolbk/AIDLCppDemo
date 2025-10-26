package com.yuandaima;

parcelable MultiString {
    // A plain UTF‑16 string.
    String utf16String;
    // A UTF‑8–encoded string (in C++ backed by std::string).
    @utf8InCpp String utf8String;
    // Another plain UTF‑16 string.
    String anotherUtf16;
    // Another UTF‑8–encoded string.
    @utf8InCpp String anotherUtf8;
    // A nullable plain UTF‑16 string.
    @nullable String nullableUtf16;
    // A nullable UTF‑8–encoded string.
    @utf8InCpp @nullable String nullableUtf8;
    // An extra plain UTF‑16 string.
    String extraUtf16;
    // An extra UTF‑8–encoded string.
    @utf8InCpp String extraUtf8;
}