#ifndef RBX_OPTIMIZED_CALL_SITE_HPP
#define RBX_OPTIMIZED_INLINE_CACHE_HPP

#include "builtin/call_site.hpp"
#include "ontology.hpp"

namespace rubinius {
  class OptimizedCallSite : public CallSite {
  public:
    const static object_type type = OptimizedCallSiteType;

  private:
    CallSite* fallback_call_site_; // slot
    OptimizedCode* optimized_code_; // slot

  public:
    attr_accessor(fallback_call_site, CallSite);
    attr_accessor(optimized_code, OptimizedCode);

    static void init(STATE);

    // Rubinius.primitive :optimized_call_site_allocate
    static OptimizedCallSite* create(STATE, CallSite* call_site, OptimizedCode*);

    static CacheExecuteFunc optimized_call_site_executor;
    static CacheUpdateFunc optimized_call_site_updater;

    static CallbackHandlerFunc on_resolved;

  public: // Rubinius Type stuff
    class Info : public CallSite::Info {
    public:
      BASIC_TYPEINFO(CallSite::Info)
      virtual void mark(Object* t, ObjectMark& mark);
    };
  };
}

#endif
