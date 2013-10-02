#include "builtin/optimized_call_site.hpp"

namespace rubinius {
  void OptimizedCallSite::init(STATE) {
    GO(optimized_call_site).set(
      ontology::new_class(state, "OptimizedCallSite",
        G(call_site), G(rubinius)));
    G(optimized_call_site)->set_object_type(state, OptimizedCallSiteType);
  }

  void OptimizedCallSite::Info::mark(Object* obj, ObjectMark& mark) {
    auto_mark(obj, mark);
  }
};
