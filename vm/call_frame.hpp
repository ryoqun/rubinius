#ifndef RBX_CALL_FRAME_HPP
#define RBX_CALL_FRAME_HPP

#include "machine_code.hpp"
#include "unwind_info.hpp"
#include "stack_variables.hpp"
#include "builtin/variable_scope.hpp"
#include "dispatch.hpp"
#include "arguments.hpp"

#include <ostream>

#ifdef ENABLE_LLVM
#include "llvm/jit_runtime.hpp"
#endif

namespace rubinius {
  class Object;
  class Symbol;
  class Module;
  class VariableScope;
  class NativeMethodFrame;

  namespace jit {
    class RuntimeData;
    class RuntimeDataHolder;
  }

  struct CallFrame {
    enum Flags {
      cIsLambda =           1 << 0,
      cCustomConstantScope =  1 << 1,
      cMultipleScopes =     1 << 2,
      cInlineFrame =        1 << 3,
      cClosedScope =        1 << 4,
      cBlockAsMethod =      1 << 5,
      cJITed =              1 << 6,
      cBlock =              1 << 7,
      cInlineBlock =        1 << 8,
      cNativeMethod =       1 << 9
    };

    CallFrame* previous;
    ConstantScope* constant_scope_;

    void* dispatch_data;
    CompiledCode* compiled_code;

    Object* self_;
    Module* module_;
    Object* block_;
    Object* last_match_;
    VariableScope* parent_;
    VariableScope* on_heap_;

    int flags;
    int ip_;

    void* optional_jit_data;
    VariableScope* top_scope_;

    Arguments* arguments;

    // Stack
    Object* stk[];

    // ACCESS

    int ip_2() {
      return ip_;
    }

    bool block_as_method_p() {
      return flags & cBlockAsMethod;
    }

    BlockEnvironment* block_env() {
      if(block_p()) {
        return reinterpret_cast<BlockEnvironment*>(dispatch_data);
      }

      return NULL;
    }

    void set_block_env(BlockEnvironment* env) {
      if(block_p()) {
        dispatch_data = reinterpret_cast<void*>(env);
      }
    }

#ifdef ENABLE_LLVM
    Symbol* name() {
      if(inline_method_p() && dispatch_data) {
        return reinterpret_cast<jit::RuntimeData*>(dispatch_data)->name();
      } else if(block_p()) {
        return reinterpret_cast<Symbol*>(cNil);
      } else if(arguments) {
        return arguments->name();
      }

      return reinterpret_cast<Symbol*>(cNil);
    }
#else
    Symbol* name() {
      if(arguments && !block_p()) {
        return arguments->name();
      }

      return reinterpret_cast<Symbol*>(cNil);
    }
#endif

#ifdef ENABLE_LLVM
    jit::RuntimeData* runtime_data() {
      if(dispatch_data) {
        if(inline_method_p()) {
          return reinterpret_cast<jit::RuntimeData*>(dispatch_data);
        }
      }

      return NULL;
    }

    jit::RuntimeDataHolder* jit_data() {
      if(jitted_p()) {
        return reinterpret_cast<jit::RuntimeDataHolder*>(optional_jit_data);
      }

      return NULL;
    }
#else
    jit::RuntimeData* runtime_data() {
      return NULL;
    }

    jit::RuntimeDataHolder* jit_data() {
      return NULL;
    }
#endif

    Symbol* original_name() {
      return compiled_code->name();
    }

    bool custom_constant_scope_p() {
      return flags & cCustomConstantScope;
    }

    bool inline_method_p() {
      return flags & cInlineFrame;
    }

    bool jitted_p() {
      return flags & cJITed;
    }

    bool block_p() {
      return flags & cBlock;
    }

    ConstantScope* constant_scope() {
      if(custom_constant_scope_p()) return constant_scope_;
      return compiled_code->scope();
    }

    bool is_block_p(STATE) {
      return block_p();
    }

    Object* self() {
      return self_;
    }

    bool multiple_scopes_p() {
      return flags & cMultipleScopes;
    }

    VariableScope* top_scope(STATE) {
      if(multiple_scopes_p()) return top_scope_;
      return promote_scope(state);
    }

    bool is_inline_frame() {
      return flags & cInlineFrame;
    }

    bool is_inline_block() {
      return flags & cInlineBlock;
    }

    bool has_closed_scope_p() {
      return flags & cClosedScope;
    }

    bool native_method_p() {
      return flags & cNativeMethod;
    }

    NativeMethodFrame* native_method_frame() {
      if(native_method_p()) return reinterpret_cast<NativeMethodFrame*>(dispatch_data);
      return 0;
    }

    CallFrame* top_ruby_frame() {
      // Skip over any native method frames.
      CallFrame* cf = this;

      while(cf->native_method_p()) {
        cf = cf->previous;
      }

      return cf;
    }

    Object* last_match(STATE);
    void set_last_match(STATE, Object* obj);

    Module* module() {
      return module_;
    }

    void set_ip(int new_ip) {
      ip_ = new_ip;
    }

    int dec_ip() {
      return ip_--;
    }

    int inc_ip() {
      return ip_++;
    }

    void calculate_ip(void** pos) {
      ip_ = pos - compiled_code->machine_code()->addresses;
    }

    VariableScope* promote_scope_full(STATE);

    VariableScope* promote_scope(STATE) {
      if(VariableScope* vs = on_heap_) return vs;
      return promote_scope_full(state);
    }

    VariableScope* method_scope(STATE);

    void print_backtrace(STATE, int count=0, bool filter=false);
    void print_backtrace(STATE, std::ostream& stream, int count=0, bool filter=false);

    Symbol* file(STATE);
    int line(STATE);

    bool scope_still_valid(VariableScope* scope);

    void dump();

    Object* find_breakpoint(STATE);

    VariableScope* on_heap() {
      return on_heap_;
    }

    bool made_alias_p() {
      return on_heap_ != 0;
    }

    void flush_to_heap(STATE);

    Object* get_local_fast(int which) {
      return stk[which];
    }

    void set_local_fast(int which, Object* val) {
      stk[which] = val;
    }

    VariableScope* create_heap_alias(STATE, bool full=true);
  };

  class InterpreterCallFrame : public CallFrame {
  public:
    // Methods

    /**
     *  Initialize frame for the given stack size.
     */
    void prepare(int stack) {
      for(int i = 0; i < stack; i++) {
        stk[i] = cNil;
      }
    }
  };

#define ALLOCA_CALLFRAME(stack_size) \
  reinterpret_cast<InterpreterCallFrame*>(alloca(sizeof(InterpreterCallFrame) + (sizeof(Object*) * (stack_size))))
};

#endif
