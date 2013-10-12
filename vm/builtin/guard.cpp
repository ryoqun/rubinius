#include "builtin/guard.hpp"
#include "ontology.hpp"

namespace rubinius {
  void Guard::init(STATE) {
    GO(guard).set(ontology::new_class(state, "Guard", G(object), G(rubinius)));
    G(optimized_call_site)->set_object_type(state, GuardType);
  }

  Guard* Guard::create(STATE, Symbol* ref, Object* object) {
    Guard* guard = state->vm()->new_object_mature<Guard>(G(guard));
    guard->class_data_ = object->direct_class(state)->data();
    guard->reference(state, ref);
    return guard;
  }

  void Guard::Info::mark(Object* obj, ObjectMark& mark) {
    auto_mark(obj, mark);
  }
}
