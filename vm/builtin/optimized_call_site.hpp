#ifndef RBX_OPTIMIZED_CALL_SITE_HPP
#define RBX_MONO_INLINE_CACHE_HPP

#include "builtin/call_site.hpp"
#include "ontology.hpp"

namespace rubinius {
  class OptimizedCallSite : public CallSite {
  public:
    const static object_type type = OptimizedCallSiteType;

  private:
    CallSite* fallback_call_site_; // slot

  public:
    attr_accessor(fallback_call_site, CallSite);

    static void init(STATE);
    static OptimizedCallSite* create(STATE, CallSite* call_site);

  public: // Rubinius Type stuff
    class Info : public CallSite::Info {
    public:
      BASIC_TYPEINFO(CallSite::Info)
      virtual void mark(Object* t, ObjectMark& mark);
    };
  };
}

#endif
