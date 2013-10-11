#ifndef RBX_OPTIMIZEDCODE_HPP
#define RBX_OPTIMIZEDCODE_HPP

#include "builtin/compiled_code.hpp"
#include "builtin/class.hpp"
#include "ontology.hpp"

namespace rubinius {
  class OptimizedCode : public CompiledCode {
  public:
    const static object_type type = OptimizedCodeType;
    CompiledCode* inlined_code_; // slot

    bool guard_p(STATE, Executable* resolved_code);

    static void init(STATE);

    attr_accessor(inlined_code, CompiledCode);

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
