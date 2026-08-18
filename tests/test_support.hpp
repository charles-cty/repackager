#pragma once

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace repackager::test {

struct TestCase {
  const char* name;
  void (*fn)();
};

inline std::vector<TestCase>& registry() {
  static std::vector<TestCase> r;
  return r;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back(TestCase{name, fn}); }
};

class Failure : public std::exception {
 public:
  explicit Failure(std::string m) : m_(std::move(m)) {}
  const char* what() const noexcept override { return m_.c_str(); }

 private:
  std::string m_;
};

inline void check(bool cond, const char* expr, const char* file, int line) {
  if (!cond) {
    throw Failure(std::string(file) + ":" + std::to_string(line) + " CHECK failed: " + expr);
  }
}

template <typename A, typename B>
void check_eq(const A& a, const B& b, const char* ea, const char* eb, const char* file, int line) {
  if (!(a == b)) {
    throw Failure(std::string(file) + ":" + std::to_string(line) + " CHECK_EQ failed: " + ea +
                  " == " + eb);
  }
}

inline int run_all() {
  int failed = 0;
  int passed = 0;
  for (const auto& t : registry()) {
    try {
      t.fn();
      std::cout << "PASS  " << t.name << '\n';
      ++passed;
    } catch (const std::exception& e) {
      std::cout << "FAIL  " << t.name << "  " << e.what() << '\n';
      ++failed;
    }
  }
  std::cout << passed << " passed, " << failed << " failed, " << (passed + failed) << " total\n";
  return failed == 0 ? 0 : 1;
}

}  // namespace repackager::test

#define TEST(name)                                                                            \
  static void test_##name();                                                                  \
  static ::repackager::test::Registrar registrar_##name(#name, test_##name);                  \
  static void test_##name()

#define CHECK(expr) ::repackager::test::check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define CHECK_EQ(a, b) ::repackager::test::check_eq((a), (b), #a, #b, __FILE__, __LINE__)
