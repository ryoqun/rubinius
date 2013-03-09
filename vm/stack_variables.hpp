#ifndef RBX_SCOPE_VARIABLES_HPP
#define RBX_SCOPE_VARIABLES_HPP

#include "builtin/object.hpp"

namespace rubinius {
  class VariableScope;

  class StackVariables {
  private: // Treat these like private!
    Object* locals_[0];

  public:
    void initialize(int locals) {
      for(int i = 0; i < locals; i++) {
        locals_[i] = cNil;
      }
    }

    friend class GarbageCollector;
    friend struct CallFrame;
  };

#define ALLOCA_STACKVARIABLES(local_size) \
  reinterpret_cast<StackVariables*>(alloca(sizeof(StackVariables) + (sizeof(Object*) * (local_size))))
}

#endif
