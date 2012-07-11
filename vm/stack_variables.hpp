#ifndef RBX_SCOPE_VARIABLES_HPP
#define RBX_SCOPE_VARIABLES_HPP

#include "builtin/object.hpp"

namespace rubinius {
  class VariableScope;
  class CallFrame;

  class StackVariables {
  public: // Treat these like private!
    VariableScope* on_heap_;
    VariableScope* parent_;
    StackVariables* stack_parent_;
    CallFrame* stack_parent_call_frame_;
    Object* self_;
    Object* block_;
    CallFrame *block_frame_;
    Module* module_;
    Object* last_match_;
    Object* locals_[0];

  public:
    void initialize(Object* self, Object* block, CallFrame *block_frame, Module* module, int locals) {
      on_heap_ = 0;
      parent_ = 0;
      stack_parent_ = 0;
      stack_parent_call_frame_ = 0;
      self_ = self;
      block_ = block;
      block_frame_ = block_frame;
      module_ = module;
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

    StackVariables* stack_parent() {
      return stack_parent_;
    }

    void set_parent(VariableScope* scope) {
      parent_ = scope;
    }

    void set_stack_parent(CallFrame* stack_parent);

    void ensure_heap_stacks(STATE, CallFrame*);

    Object* self() {
      return self_;
    }

    Object* block() {
      return block_;
    }

    CallFrame* block_frame() {
      return block_frame_;
    }

    Module* module() {
      return module_;
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

    VariableScope* create_heap_alias(STATE, CallFrame* call_frame);
    void flush_to_heap(STATE);

    friend class GarbageCollector;
  };

#define ALLOCA_STACKVARIABLES(local_size) \
  (StackVariables*)alloca(sizeof(StackVariables) + (sizeof(Object*) * local_size))
}

#endif
