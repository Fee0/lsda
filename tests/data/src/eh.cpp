// Fixtures for the lsda tests: the kinds of LSDA content that GCC and clang
// emit. Compiled with -std=c++14 for dynamic exception specifications.
struct E1 {
  int x;
};
struct E2 : E1 {};
struct Guard {
  Guard();
  ~Guard();
};

void may_throw();
void may_throw_int(int);

extern "C" {

// A cleanup only: a call site with a landing pad and no action.
void cleanup_only() {
  Guard g;
  may_throw();
}

// catch (int).
int catch_int() {
  try {
    may_throw();
  } catch (int i) {
    return i;
  }
  return 0;
}

// Several handlers, ending with catch (...).
int catch_many() {
  try {
    may_throw();
  } catch (E2 &) {
    return 2;
  } catch (E1 &) {
    return 1;
  } catch (const char *) {
    return 3;
  } catch (...) {
    return 4;
  }
  return 0;
}

// Nested try blocks with a cleanup between them.
int nested() {
  try {
    Guard g;
    try {
      may_throw();
    } catch (E1 &) {
      may_throw_int(1);
    }
    may_throw();
  } catch (int) {
    return 1;
  }
  return 0;
}

// Dynamic exception specifications.
void spec_one() throw(int) { may_throw(); }
void spec_two() throw(int, E1) {
  Guard g;
  may_throw();
}
void spec_none() throw() { may_throw(); }

// noexcept: the call site has no landing pad and no action, or terminates.
void no_except() noexcept {
  Guard g;
  may_throw();
}

// Rethrow from a handler with a cleanup.
void rethrow() {
  try {
    may_throw();
  } catch (...) {
    Guard g;
    throw;
  }
}

// A handler inside an exception specification.
int spec_and_catch() throw(E1) {
  try {
    may_throw();
  } catch (int) {
    return 1;
  }
  return 0;
}

// Enough call sites and actions for multi-byte LEB128 values.
#define T(n)                                                                   \
  try {                                                                        \
    may_throw_int(n);                                                          \
  } catch (int) {                                                              \
    may_throw_int(-n);                                                         \
  } catch (E1 &) {                                                             \
    may_throw_int(n + 1000);                                                   \
  }
#define T10(n) T(n) T(n + 1) T(n + 2) T(n + 3) T(n + 4) T(n + 5) T(n + 6) T(n + 7) T(n + 8) T(n + 9)
void many_handlers() {
  Guard g;
  T10(0) T10(10) T10(20) T10(30)
}
}
