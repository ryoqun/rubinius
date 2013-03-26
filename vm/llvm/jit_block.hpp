#include "llvm/jit_builder.hpp"

namespace rubinius {
namespace jit {
  class BlockBuilder : public Builder {
    llvm::Value* module_;

  public:
    BlockBuilder(Context* ctx, JITMethodInfo& info)
      : Builder(ctx, info)
    {}

    void initialize_frame();
    void setup_block_scope();
    void setup();
    void import_args_19_style();

  protected:
    llvm::Value* inv_flags_;
  };
}
}
