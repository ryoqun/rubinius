#include "builtin/optimized_call_site.hpp"

namespace rubinius {
  void OptimizedCallSite::init(STATE) {
    GO(optimized_call_site).set(
      ontology::new_class(state, "OptimizedCallSite",
        G(call_site), G(rubinius)));
    G(optimized_call_site)->set_object_type(state, OptimizedCallSiteType);
  }

  OptimizedCallSite* OptimizedCallSite::create(STATE, CallSite* unoptimized) {
    OptimizedCallSite* call_site =
      state->vm()->new_object_mature<OptimizedCallSite>(G(optimized_call_site));
    call_site->name_     = unoptimized->name();
    call_site->executable(state, unoptimized->executable());
    call_site->ip_       = unoptimized->ip();
    call_site->executor_ = empty_cache;
    call_site->fallback_ = unoptimized->fallback_;
    call_site->updater_  = empty_cache_updater;
    call_site->fallback_call_site(state, unoptimized);
    return call_site;
  }

  void OptimizedCallSite::Info::mark(Object* obj, ObjectMark& mark) {
    auto_mark(obj, mark);
  }
};
