#ifndef RBX_LLVM_JIT_COMPILER_HPP
#define RBX_LLVM_JIT_COMPILER_HPP

#include <llvm/CodeGen/MachineCodeInfo.h>

#include "llvm/jit_context.hpp"

namespace llvm {
  class Function;
  class MachineCodeInfo;
  class BasicBlock;
  class Value;
}

namespace rubinius {
  class LLVMState;
  class JITMethodInfo;
  class MachineCode;
  class BackgroundCompileRequest;

namespace jit {
  class Builder;

  class Compiler {
    Context* ctx_;
    llvm::Function* function_;
    llvm::MachineCodeInfo* mci_;

  public:
    Compiler(Context* ctx)
      : ctx_(ctx)
      , function_(0)
      , mci_(0)
    {}

    ~Compiler() {
      if(function_) delete function_;
      delete mci_;
    }

    int code_bytes() {
      return mci_->size();
    }

    llvm::Function* llvm_function() {
      return function_;
    }

    Context* context() {
      return ctx_;
    }

    JITMethodInfo* info() {
      return ctx_->root();
    }

    void compile(BackgroundCompileRequest* req);
    void compile_method(BackgroundCompileRequest* req);
    void compile_block(BackgroundCompileRequest* req);
    void compile_builder(JITMethodInfo&, rubinius::jit::Builder&);

    void* function_pointer();
    void* generate_function(bool indy=true);
    void show_machine_code();
  };
}
}

#endif
