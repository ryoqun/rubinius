#include "stack_variables.hpp"
#include "builtin/variable_scope.hpp"
#include "builtin/lookuptable.hpp"
#include "machine_code.hpp"
#include "call_frame.hpp"

namespace rubinius {

  VariableScope* StackVariables::create_heap_alias(STATE, CallFrame* call_frame,
                                                   bool full)
  {
    if(call_frame->on_heap_) return call_frame->on_heap_;

    MachineCode* mcode = call_frame->compiled_code->machine_code();
    VariableScope* scope = state->new_object_dirty<VariableScope>(G(variable_scope));

    if(call_frame->parent_) {
      scope->parent(state, call_frame->parent_);
    } else {
      scope->parent(state, nil<VariableScope>());
    }

    scope->self(state, call_frame->self_);
    scope->block(state, call_frame->block_);
    scope->module(state, call_frame->module_);
    scope->method(state, call_frame->compiled_code);
    scope->heap_locals(state, Tuple::create(state, mcode->number_of_locals));
    scope->last_match(state, call_frame->last_match_);
    scope->fiber(state, state->vm()->current_fiber.get());

    scope->number_of_locals_ = mcode->number_of_locals;

    if(full) {
      scope->isolated_ = false;
    } else {
      scope->isolated_ = true;
    }

    scope->locals_ = locals_;
    scope->dynamic_locals(state, nil<LookupTable>());

    scope->set_block_as_method(call_frame->block_as_method_p());

    call_frame->on_heap_ = scope;

    return scope;
  }
}
