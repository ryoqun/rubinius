#include "stack_variables.hpp"
#include "builtin/variable_scope.hpp"
#include "vmmethod.hpp"
#include "call_frame.hpp"
#include "builtin/block_environment.hpp"

namespace rubinius {

  void StackVariables::ensure_heap_stacks(STATE, CallFrame* call_frame)
  {
    /*StackVariables* scope = this;
    while(scope) {
      StackVariables* parent = scope->stack_parent_;
      VariableScope* variable_scope = scope->promote_sccope(state);
      scope->parent_ = variable_scope
      variable_scope->parent(state, kkkk
      if(!try_as<VariableScope*>(scope->parent())) {
        scope->parent(state, scope->stack_parent_call_frame_->promote_scope(state));
      scope->parent(state, parent_);
      }

      scope->stack_parent_ = NULL;
      scope->stack_parent_call_frame_ = NULL;
      scope = parent;
    }*/
    StackVariables* current_scope = this;
    CallFrame* current_call_frame = call_frame;
    //std::cout << "begin" << std::endl;
    while(current_scope) {
      //std::cout << "inside loop" << std::endl;
      StackVariables* parent_scope = current_scope->stack_parent_;
      CallFrame* parent_call_frame = current_scope->stack_parent_call_frame_;
      VariableScope* current_variable_scope = current_call_frame->promote_scope(state);

      if(parent_scope) {
        VariableScope* parent_variable_scope = parent_call_frame->promote_scope(state);
        current_variable_scope->parent(state, parent_variable_scope);
        current_scope->parent_ = parent_variable_scope;
        current_scope->stack_parent_ = NULL;
        current_scope->stack_parent_call_frame_ = NULL;
      }

      current_scope = parent_scope;
      current_call_frame = parent_call_frame;
    }
  }

  void StackVariables::set_stack_parent(CallFrame* stack_parent) {
    if(stack_parent) {
      stack_parent_call_frame_ = stack_parent;
      stack_parent_ = stack_parent->scope;
    }
  }

  VariableScope* StackVariables::create_heap_alias(STATE, CallFrame* call_frame)
  {
    if(on_heap_) return on_heap_;

    VMMethod* vmm = call_frame->cm->backend_method();
    VariableScope* scope = state->new_object<VariableScope>(G(variable_scope));

    if(parent_) {
      scope->parent(state, parent_);
    } else {
      scope->parent(state, nil<VariableScope>());
    }

    scope->self(state, self_);
    scope->block(state, block_);
    scope->module(state, module_);
    scope->method(state, call_frame->cm);
    scope->heap_locals(state, Tuple::create(state, vmm->number_of_locals));
    scope->last_match(state, last_match_);
    scope->fiber(state, state->vm()->current_fiber.get());

    scope->number_of_locals_ = vmm->number_of_locals;
    scope->block_frame_ = block_frame_;

    scope->isolated_ = false;

    scope->locals_ = locals_;

    scope->set_block_as_method(call_frame->block_as_method_p());

    on_heap_ = scope;

    return scope;
  }

  void StackVariables::set_last_match(STATE, Object* obj) {
    // For closures, get back to the top of the chain and set the
    // last_match there. This means that the last_match is shared
    // amongst all closures in a method, but thats how it's implemented
    // in ruby.
    if(parent_) {
      VariableScope* scope = parent_;
      while(CBOOL(scope->parent())) {
        scope = scope->parent();
      }

      return scope->last_match(state, obj);
    }

    // Use a heap alias if there is one.
    if(on_heap_) {
      on_heap_->last_match(state, obj);

    // Otherwise, use the local one. This is where a last_match usually
    // first appears.
    } else {
      last_match_ = obj;
    }
  }

  Object* StackVariables::last_match(STATE) {
    // For closures, get back to the top of the chain and get that
    // last_match.
    if(parent_) {
      VariableScope* scope = parent_;
      while(CBOOL(scope->parent())) {
        scope = scope->parent();
      }

      return scope->last_match();
    }

    // Otherwise, if this has a heap alias, get the last_match from there.
    if(on_heap_) {
      return on_heap_->last_match();

    // Lastly, use the local one. This is where a last_match begins life.
    } else {
      return last_match_;
    }
  }

  void StackVariables::flush_to_heap(STATE) {
    if(!on_heap_) return;

    on_heap_->isolated_ = true;

    //if(CompiledMethod* cm = try_as<CompiledMethod>(on_heap_->block())) {
    //  cm->scope(state, on_heap_->block_frame_->constant_scope());
    //  GCTokenImpl gct;
    //  BlockEnvironment* env = BlockEnvironment::under_call_frame(state, gct, cm, on_heap_->block_frame_);
    //  on_heap_->block(state, env);
    //}

    for(int i = 0; i < on_heap_->number_of_locals_; i++) {
      on_heap_->set_local(state, i, locals_[i]);
    }
  }
}
