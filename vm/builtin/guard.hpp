#ifndef RBX_GUARD_HPP
#define RBX_GUARD_HPP

#include "builtin/object.hpp"
#include "builtin/class.hpp"
#include "builtin/fixnum.hpp"
#include "builtin/tuple.hpp"

namespace rubinius {
  class Guard : public Object {
    public:
      const static object_type type = GuardType;

    private:
      ClassData class_data_;
      Symbol* reference_; // slot

    public:
      attr_accessor(reference, Symbol);

    static void init(STATE);

    // Rubinius.primitive :guard_allocate
    static Guard* create(STATE, Symbol* ref, Object* obj);

    ClassData class_data() {
      return class_data_;
    }

    // Rubinius.primitive :guard_class_data
    Tuple* class_data_prim(STATE) {
      return Tuple::from(state,
                         2,
                         Fixnum::from(class_data_.f.class_id),
                         Fixnum::from(class_data_.f.serial_id));
    }

  public: // Rubinius Type stuff
    class Info : public Object::Info {
    public:
      BASIC_TYPEINFO(Object::Info)
      virtual void mark(Object* t, ObjectMark& mark);
    };
  };
}
#endif
