#ifndef RBX_OPTIMIZEDCODE_HPP
#define RBX_OPTIMIZEDCODE_HPP

#include "builtin/compiledcode.hpp"
#include "builtin/class.hpp"
#include "ontology.hpp"

namespace rubinius {
  class OptimizedCode : public CompiledCode {
  public:
    const static object_type type = OptimizedCodeType;

    static void init(STATE);

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
