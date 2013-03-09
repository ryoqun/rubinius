#ifndef RBX_SCOPE_VARIABLES_HPP
#define RBX_SCOPE_VARIABLES_HPP

#include "builtin/object.hpp"

namespace rubinius {
  class VariableScope;

  class StackVariables {
  public: // Treat these like private!
    Object* locals_[0];

  public:
    void initialize(int locals) {
      for(int i = 0; i < locals; i++) {
        locals_[i] = cNil;
      }
    }

    VariableScope* create_heap_alias(STATE, CallFrame* call_frame, bool full=true);
    friend class GarbageCollector;
  };

#define ALLOCA_STACKVARIABLES(local_size) \
  reinterpret_cast<StackVariables*>(alloca(sizeof(StackVariables) + (sizeof(Object*) * local_size)))
}

#endif
