#include <iostream>

#include "call_frame.hpp"
#include "builtin/variable_scope.hpp"
#include "builtin/class.hpp"
#include "builtin/module.hpp"
#include "builtin/symbol.hpp"
#include "builtin/compiledcode.hpp"
#include "builtin/tuple.hpp"
#include "builtin/constantscope.hpp"
#include "builtin/lookuptable.hpp"
#include "builtin/nativemethod.hpp"

#include "object_utils.hpp"

namespace rubinius {
  Object* CallFrame::last_match(STATE) {
    CallFrame* use = this->top_ruby_frame();;

    while(use && use->is_inline_block()) {
      CallFrame* yielder = use->previous;
      if(!yielder) return cNil;
      // This works because the creator is always one above
      // the yielder with inline blocks.
      use = yielder->previous;
    }

    if(!use) return cNil;
    // For closures, get back to the top of the chain and get that
    // last_match.
    if(use->parent_) {
      VariableScope* scope = use->parent_;
      while(CBOOL(scope->parent())) {
        scope = scope->parent();
      }

      return scope->last_match();
    }

    // Otherwise, if this has a heap alias, get the last_match from there.
    if(use->on_heap_) {
      return use->on_heap_->last_match();

    // Lastly, use the local one. This is where a last_match begins life.
    } else {
      if(!last_match_) {
        last_match_ = cNil;
      }
      return last_match_;
    }
  }

  void CallFrame::set_last_match(STATE, Object* obj) {
    CallFrame* use = this->top_ruby_frame();

    while(use && use->is_inline_block()) {
      CallFrame* yielder = use->previous;
      if(!yielder) return;
      // This works because the creator is always one above
      // the yielder with inline blocks.
      use = yielder->previous;
    }

    if(!use) return;
    // For closures, get back to the top of the chain and set the
    // last_match there. This means that the last_match is shared
    // amongst all closures in a method, but thats how it's implemented
    // in ruby.
    if(use->parent_) {
      VariableScope* scope = use->parent_;
      while(CBOOL(scope->parent())) {
        scope = scope->parent();
      }

      return scope->last_match(state, obj);
    }

    // Use a heap alias if there is one.
    if(use->on_heap_) {
      use->on_heap_->last_match(state, obj);

    // Otherwise, use the local one. This is where a last_match usually
    // first appears.
    } else {
      last_match_ = obj;
    }
  }

  VariableScope* CallFrame::promote_scope_full(STATE) {
    return create_heap_alias(state, !has_closed_scope_p());
  }

  VariableScope* CallFrame::method_scope(STATE) {
    VariableScope* current = promote_scope(state);
    if(!multiple_scopes_p()) return current;

    for(;;) {
      if(current->block_as_method_p()) return current;
      VariableScope* parent = current->parent();
      if(!parent->nil_p()) {
        current = parent;
      } else {
        return current;
      }
    }

    // Shouldn't ever get here.
    return 0;
  }

  void CallFrame::print_backtrace(STATE, int total, bool filter) {
    print_backtrace(state, std::cout, total, filter);
  }

  void CallFrame::print_backtrace(STATE, std::ostream& stream, int total, bool filter) {
    CallFrame* cf = this;

    int i = -1;

    while(cf) {
      i++;

      if(total > 0 && i == total) return;

      if(NativeMethodFrame* nmf = cf->native_method_frame()) {
        stream << static_cast<void*>(cf) << ": ";
        NativeMethod* nm = try_as<NativeMethod>(nmf->get_object(nmf->method()));
        if(nm && nm->name()->symbol_p()) {
          stream << "capi:" << nm->name()->debug_str(state) << " at ";
          stream << nm->file()->c_str(state);
        } else {
          stream << "unknown capi";
        }

        stream << std::endl;
        cf = cf->previous;
        continue;
      }

      if(!cf->compiled_code) {
        cf = cf->previous;
        continue;
      }

      if(filter && cf->compiled_code->kernel_method(state)) {
        cf = cf->previous;
        continue;
      }

      stream << static_cast<void*>(cf) << ": ";

      if(cf->is_block_p(state)) {
        stream << "__block__";
      } else {
        if(SingletonClass* sc = try_as<SingletonClass>(cf->module())) {
          Object* obj = sc->attached_instance();

          if(Module* mod = try_as<Module>(obj)) {
            stream << mod->debug_str(state) << ".";
          } else {
            if(obj == G(main)) {
              stream << "MAIN.";
            } else {
              stream << "#<" << obj->class_object(state)->debug_str(state) <<
                        ":" << (void*)obj->id(state)->to_native() << ">.";
            }
          }
        } else if(IncludedModule* im = try_as<IncludedModule>(cf->module())) {
          stream <<  im->module()->debug_str(state) << "#";
        } else {
          Symbol* name;
          std::string mod_name;

          if(cf->module()->nil_p()) {
            mod_name = cf->compiled_code->scope()->module()->debug_str(state);
          } else {
            if((name = try_as<Symbol>(cf->module()->module_name()))) {
              mod_name = name->debug_str(state);
            } else if((name = try_as<Symbol>(
                      cf->compiled_code->scope()->module()->module_name()))) {
              mod_name = name->debug_str(state);
            } else {
              mod_name = "<anonymous module>";
            }
          }
          stream << mod_name << "#";
        }

        Symbol* name = try_as<Symbol>(cf->name());
        if(name) {
          stream << name->debug_str(state);
        } else {
          stream << cf->compiled_code->name()->debug_str(state);
        }
      }

      stream << " in ";
      if(Symbol* file_sym = try_as<Symbol>(cf->compiled_code->file())) {
        stream << file_sym->debug_str(state) << ":" << cf->line(state);
      } else {
        stream << "<unknown>";
      }

      stream << " (+" << cf->ip_2();
      if(cf->is_inline_frame()) {
        stream << " inline";
      } else if(cf->jitted_p()) {
        stream << " jit";
      }
      stream << ")";

      stream << std::endl;
      cf = cf->previous;
    }

  }

  Symbol* CallFrame::file(STATE) {
    if(compiled_code) {
      return compiled_code->file();
    } else {
      return nil<Symbol>();
    }
  }

  int CallFrame::line(STATE) {
    if(!compiled_code) return -2;        // trampoline context
    return compiled_code->line(state, ip_2());
  }

  // Walks the CallFrame list to see if +scope+ is still running
  bool CallFrame::scope_still_valid(VariableScope* scope) {
    CallFrame* cur = this;
    while(cur) {
      if(cur->on_heap() == scope) return true;
      cur = cur->previous;
    }

    return false;
  }

  void CallFrame::dump() {
    VM* vm = VM::current();
    State state_obj(vm), *state = &state_obj;

    std::cout << "<CallFrame:" << (void*)this << " ";

    if(native_method_p()) {
      std::cout << "capi>\n";
      return;
    }

    if(is_inline_frame()) {
      std::cout << "inline ";
    }

    if(is_block_p(state)) {
      std::cout << "block ";
    } else if(dispatch_data) {
      std::cout << "name=" << name()->debug_str(state) << " ";
    } else {
      std::cout << "name=" << compiled_code->name()->debug_str(state) << " ";
    }

    std::cout << "ip=" << ip_ << " ";

    std::cout << "line=" << line(state);

    std::cout << ">\n";
  }

  Object* CallFrame::find_breakpoint(STATE) {
    if(!compiled_code) return 0;

    LookupTable* tbl = compiled_code->breakpoints();
    if(tbl->nil_p()) return 0;

    bool found = false;

    Object* obj = tbl->fetch(state, Fixnum::from(ip_2()), &found);
    if(found) return obj;

    return 0;
  }

  void CallFrame::flush_to_heap(STATE) {
    if(!on_heap_) return;

    int offset = compiled_code->machine_code()->stack_size;
    on_heap_->isolated_ = true;

    for(int i = 0; i < on_heap_->number_of_locals_; i++) {
      on_heap_->set_local(state, i, get_local_fast(offset + i));
    }
  }

  VariableScope* CallFrame::create_heap_alias(STATE, bool full)
  {
    if(on_heap_) return on_heap_;

    MachineCode* mcode = compiled_code->machine_code();
    VariableScope* new_scope = state->new_object_dirty<VariableScope>(G(variable_scope));

    if(parent_) {
      new_scope->parent(state, parent_);
    } else {
      new_scope->parent(state, nil<VariableScope>());
    }

    if(!last_match_) {
      last_match_ = cNil;
    }

    new_scope->self(state, self_);
    new_scope->block(state, block_);
    new_scope->module(state, module_);
    new_scope->method(state, compiled_code);
    new_scope->heap_locals(state, Tuple::create(state, mcode->number_of_locals));
    new_scope->last_match(state, last_match_);
    new_scope->fiber(state, state->vm()->current_fiber.get());

    new_scope->number_of_locals_ = mcode->number_of_locals;

    if(full) {
      new_scope->isolated_ = false;
    } else {
      new_scope->isolated_ = true;
    }

    new_scope->locals_ = stk + compiled_code->machine_code()->stack_size;
    new_scope->dynamic_locals(state, nil<LookupTable>());

    new_scope->set_block_as_method(block_as_method_p());

    on_heap_ = new_scope;

    return new_scope;
  }

  /* For debugging. */
  extern "C" {
    void __printbt__(CallFrame* call_frame) {
      State state(VM::current());
      call_frame->print_backtrace(&state);
    }
  }
}
