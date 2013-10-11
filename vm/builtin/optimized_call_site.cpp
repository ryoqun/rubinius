#include "builtin/optimized_call_site.hpp"
#include "builtin/optimized_code.hpp"
#include "builtin/mono_inline_cache.hpp"
#include "call_frame.hpp"

namespace rubinius {
  void OptimizedCallSite::init(STATE) {
    GO(optimized_call_site).set(
      ontology::new_class(state, "OptimizedCallSite",
        G(call_site), G(rubinius)));
    G(optimized_call_site)->set_object_type(state, OptimizedCallSiteType);
  }

  OptimizedCallSite* OptimizedCallSite::create(STATE, CallSite* unoptimized, OptimizedCode* optimized_code) {
    OptimizedCallSite* call_site =
      state->vm()->new_object_mature<OptimizedCallSite>(G(optimized_call_site));
    call_site->name_     = unoptimized->name();
    call_site->executable(state, unoptimized->executable());
    call_site->ip_       = unoptimized->ip();
    call_site->executor_ = optimized_call_site_executor;
    call_site->fallback_ = unoptimized->fallback_;
    call_site->updater_  = optimized_call_site_updater;
    call_site->fallback_call_site(state, unoptimized);
    call_site->optimized_code(state, optimized_code);
    return call_site;
  }

  Object* OptimizedCallSite::optimized_call_site_executor(STATE, CallSite* call_site, CallFrame* call_frame,
                             Arguments& args, CallbackHandler handler)
  {
    OptimizedCallSite* optimized = reinterpret_cast<OptimizedCallSite*>(call_site);
    Object* next = optimized->fallback_call_site_->executor_(state, optimized->fallback_call_site_, call_frame, args, on_resolved);
    return next;
  }

  void OptimizedCallSite::optimized_call_site_updater(STATE, CallSite* call_site, Class* klass, Dispatch& dispatch) {
    //OptimizedCallSite* optimized = reinterpret_cast<OptimizedCallSite*>(call_site);
    //MonoInlineCache* mono_cache = reinterpret_cast<MonoInlineCache*>(optimized->fallback_call_site_);

    //if(klass == mono_cache->receiver_class_) {
    //  CallSite::empty_cache_updater(state, mono_cache, klass, dispatch);
    //}
  }

  Object* OptimizedCallSite::on_resolved(STATE,
                                         CallSite* call_site,
                                         CallFrame* frame,
                                         Executable* executable,
                                         Module* mod,
                                         Arguments& args) {
    OptimizedCallSite* optimized = (OptimizedCallSite*)frame->compiled_code->current_call_site(state, frame->previous, frame->ip());
    OptimizedCode* code = optimized->optimized_code();
    if(code->guard_p(state, executable)) {
      return code->execute(state, frame, code, mod, args);
    } else {
      return executable->execute(state, frame, executable, mod, args);
    }
  }

  void OptimizedCallSite::Info::mark(Object* obj, ObjectMark& mark) {
    auto_mark(obj, mark);
  }
};
