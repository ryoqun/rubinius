#ifndef RBX_OPTIMIZEDCODE_HPP
#define RBX_OPTIMIZEDCODE_HPP

#include "builtin/compiled_code.hpp"
#include "builtin/class.hpp"
#include "ontology.hpp"

namespace rubinius {
  class OptimizedCode : public CompiledCode {
  public:
    const static object_type type = OptimizedCodeType;
    CompiledCode* original_code_; // slot
    Tuple* guards_;               // slot

    bool guard_p(STATE, CallFrame*, Executable* resolved_code, Module*, Arguments& args);
    bool guard_label_p(STATE, Symbol* label, Class* current_class, CallFrame* frame, Module* mod, Arguments& args);

    static void init(STATE);

    attr_accessor(original_code, CompiledCode);
    attr_accessor(guards, Tuple);

    // Rubinius.primitive :optimizedcode_allocate
    static OptimizedCode* create(STATE);

    class Info : public CompiledCode::Info {
    public:
      BASIC_TYPEINFO(CompiledCode::Info)
      virtual void mark(Object* obj, ObjectMark& mark);
      virtual void show(STATE, Object* self, int level);
    };
  };
}

#endif
