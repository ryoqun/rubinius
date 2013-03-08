#ifndef RBX_SCOPE_VARIABLES_HPP
#define RBX_SCOPE_VARIABLES_HPP

#include "builtin/object.hpp"

namespace rubinius {
  class VariableScope;

  class StackVariables {
  public: // Treat these like private!
    VariableScope* on_heap_;
    VariableScope* parent_;
    Object* block_;
    Object* last_match_;
    Object* locals_[0];

  public:
    void initialize(Object* block, int locals) {
      on_heap_ = 0;
      parent_ = 0;
      block_ = block;
      last_match_ = cNil;

      for(int i = 0; i < locals; i++) {
        locals_[i] = cNil;
      }
    }

    VariableScope* on_heap() {
      return on_heap_;
    }

    VariableScope* parent() {
      return parent_;
    }

    void set_parent(VariableScope* scope) {
      parent_ = scope;
    }

    Object* block() {
      return block_;
    }

    bool made_alias_p() {
      return on_heap_ != 0;
    }

    Object* get_local(int which) {
      return locals_[which];
    }

    void set_local(int which, Object* val) {
      locals_[which] = val;
    }

    void set_last_match(STATE, Object* obj);

    Object* last_match(STATE);

    VariableScope* create_heap_alias(STATE, CallFrame* call_frame, bool full=true);
    void flush_to_heap(STATE);

    friend class GarbageCollector;
  };

#define ALLOCA_STACKVARIABLES(local_size) \
  reinterpret_cast<StackVariables*>(alloca(sizeof(StackVariables) + (sizeof(Object*) * local_size)))
}

#endif
