#ifndef RBX_SCOPE_VARIABLES_HPP
#define RBX_SCOPE_VARIABLES_HPP

#include "builtin/object.hpp"

namespace rubinius {
  class VariableScope;

  class StackVariables {
  private: // Treat these like private!
    Object* locals_[0];

  public:
    friend class GarbageCollector;
    friend struct CallFrame;
  };
}

#endif
