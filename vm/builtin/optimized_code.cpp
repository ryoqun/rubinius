#include "builtin/optimized_code.hpp"
#include "object_utils.hpp"

namespace rubinius {
  void OptimizedCode::init(STATE) {
    GO(optimized_code).set(ontology::new_class(state,
                      "OptimizedCode", G(compiled_code), G(rubinius)));
    G(optimized_code)->set_object_type(state, OptimizedCodeType);
  }

  OptimizedCode* OptimizedCode::create(STATE) {
    OptimizedCode* code = state->new_object<OptimizedCode>(G(optimized_code));
    code->local_count(state, Fixnum::from(0));
    code->inliners_ = 0;
    code->prim_index_ = -1;
    code->custom_call_site_ = false;

    code->set_executor(CompiledCode::default_executor);
    code->machine_code_ = NULL;
#ifdef ENABLE_LLVM
    code->jit_data_ = NULL;
#endif

    return code;
  }

  bool OptimizedCode::guard_p(STATE, CompiledCode* resolved_code) {
    //printf("guard %p %p\n", try_as<CompiledCode>(resolved_code), try_as<CompiledCode>(inlined_code_));
    //printf("guard %p %p\n", resolved_code, inlined_code());
    //return true;
    if(resolved_code == inlined_code()) {
      return true;
    } else {
      return false;
    }
  }

  void OptimizedCode::Info::mark(Object* obj, ObjectMark& mark) {
    CompiledCode::Info::mark(obj, mark);
  }

  void OptimizedCode::Info::show(STATE, Object* self, int level) {
    CompiledCode::Info::show(state, self, level);
  }
}
