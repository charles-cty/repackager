#pragma once

#include <string>
#include <utility>
#include <variant>

namespace repackager {

enum class ExitCode : int {
  Success = 0,
  Internal = 1,
  Usage = 2,
  NotFound = 3,
  Conflict = 4,
  Validation = 5,
  SignatureConsent = 6,
  Elevation = 7,
  RolledBack = 8,
  Environment = 9,
};

struct Error {
  ExitCode code = ExitCode::Internal;
  std::string message;
};

template <typename T>
class Expected {
 public:
  Expected() = default;

  static Expected ok(T value) {
    Expected e;
    e.storage_ = std::move(value);
    return e;
  }

  static Expected fail(ExitCode code, std::string message) {
    Expected e;
    e.storage_ = Error{code, std::move(message)};
    return e;
  }

  static Expected fail(Error error) {
    Expected e;
    e.storage_ = std::move(error);
    return e;
  }

  bool has_value() const { return std::holds_alternative<T>(storage_); }
  explicit operator bool() const { return has_value(); }

  const T& value() const { return std::get<T>(storage_); }
  T& value() { return std::get<T>(storage_); }
  T take() { return std::get<T>(std::move(storage_)); }

  const Error& error() const { return std::get<Error>(storage_); }
  ExitCode code() const {
    return has_value() ? ExitCode::Success : std::get<Error>(storage_).code;
  }
  const std::string& message() const {
    static const std::string empty;
    return has_value() ? empty : std::get<Error>(storage_).message;
  }

 private:
  std::variant<T, Error> storage_{Error{ExitCode::Internal, "uninitialized"}};
};

struct Status {
  bool ok = true;
  ExitCode code = ExitCode::Success;
  std::string message;

  static Status success(std::string message = {}) {
    return Status{true, ExitCode::Success, std::move(message)};
  }
  static Status fail(ExitCode code, std::string message) {
    return Status{false, code, std::move(message)};
  }
  explicit operator bool() const { return ok; }
};

const char* exit_code_name(ExitCode code);

}  // namespace repackager
