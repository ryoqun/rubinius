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
    call_site->executor_ = optimized_call_site_executor;
    call_site->fallback_ = unoptimized->fallback_;
    call_site->updater_  = optimized_call_site_updater;
    call_site->fallback_call_site(state, unoptimized);
    return call_site;
  }

  Object* OptimizedCallSite::optimized_call_site_executor(STATE, CallSite* call_site, CallFrame* call_frame,
                             Arguments& args, CallbackHandler handler)
  {
    OptimizedCallSite* optimized = reinterpret_cast<OptimizedCallSite*>(call_site);
    handler = (handler) ? handler : on_executable_resolved;
    return optimized->fallback_call_site_->executor_(state, call_site, call_frame, args, handler);
  }

  void OptimizedCallSite::optimized_call_site_updater(STATE, CallSite* call_site, Class* klass, Dispatch& dispatch) {
  }

  void OptimizedCallSite::on_executable_resolved(Executable *executable) {
    printf("%p\n", executable);
  }

  void OptimizedCallSite::Info::mark(Object* obj, ObjectMark& mark) {
    auto_mark(obj, mark);
  }
};
