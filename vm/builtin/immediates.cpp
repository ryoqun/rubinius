#include "builtin/immediates.hpp"

#include <iostream>

namespace rubinius {

  void FalseClass::Info::mark(Object*, ObjectMark&) { }

  void FalseClass::Info::show(UNUSED_STATE, Object*, int) {
    std::cout << "'false'" << std::endl;
  }

  void TrueClass::Info::mark(Object*, ObjectMark&) { }

  void TrueClass::Info::show(UNUSED_STATE, Object*, int) {
    std::cout << "'true'" << std::endl;
  }

  void NilClass::Info::mark(Object*, ObjectMark&) { }

  void NilClass::Info::show(UNUSED_STATE, Object*, int) {
    std::cout << "nil" << std::endl;
  }

  void NilClass::Info::show_simple(STATE, Object* self, int level) {
    show(state, self, level);
  }
}
