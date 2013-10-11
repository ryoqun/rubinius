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
    printf("YAAAAAAY!!! mine %p\n", optimized);
    printf("YAAAAAAY!!! %p\n", optimized->optimized_code());
    printf("YAAAAAAY!!! %p\n", optimized->optimized_code()->inlined_code());
    handler = (handler) ? handler : on_resolved;
    printf("%p\n", optimized->fallback_call_site_->executor_);
    printf("aaa %p\n", handler);
    Object* next = optimized->fallback_call_site_->executor_(state, optimized->fallback_call_site_, call_frame, args, handler);
    printf("aaa %p\n", handler);
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
    printf("YAAAAAAY!!! %p\n", optimized);
    printf("YAAAAAAY!!! %d\n", frame->ip());
    printf("YAAAAAAY!!! %p\n", optimized->optimized_code());
    printf("YAAAAAAY!!! %p\n", optimized->optimized_code()->inlined_code());
    CompiledCode *resolved_code = try_as<CompiledCode>(executable);
    if(resolved_code && optimized->optimized_code()->guard_p(state, resolved_code)) {
      return optimized->optimized_code()->execute(state, frame, resolved_code, mod, args);
    } else {
      return resolved_code->execute(state, frame, resolved_code, mod, args);
    }
  }

  void OptimizedCallSite::Info::mark(Object* obj, ObjectMark& mark) {
    auto_mark(obj, mark);
  }
};
