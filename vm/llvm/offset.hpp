#ifndef RBX_LLVM_OFFSET_HPP
#define RBX_LLVM_OFFSET_HPP

namespace offset {
namespace Arguments {
  const static int name = 0;
  const static int recv = 1;
  const static int block = 2;
  const static int total = 3;
  const static int arguments = 4;
  const static int argument_container = 5;
}
namespace Array {
  const static int header = 0;
  const static int total = 1;
  const static int tuple = 2;
  const static int start = 3;
  const static int shared = 4;
}
namespace BlockEnvironment {
  const static int header = 0;
  const static int scope = 1;
  const static int top_scope = 2;
  const static int code = 3;
  const static int module = 4;
}
namespace BlockInvocation {
  const static int flags = 0;
  const static int self = 1;
  const static int constant_scope = 2;
  const static int module = 3;
}
namespace ByteArray {
  const static int header = 0;
  const static int full_size = 1;
  const static int field = 2;
}
namespace CallFrame {
  const static int previous = 0;
  const static int constant_scope = 1;
  const static int dispatch_data = 2;
  const static int compiled_code = 3;
  const static int self = 4;
  const static int flags = 5;
  const static int ip = 6;
  const static int jit_data = 7;
  const static int top_scope = 8;
  const static int scope = 9;
  const static int arguments = 10;
  const static int stk = 11;
}
namespace Class {
  const static int header = 0;
  const static int instance_type = 1;
  const static int packed_ivar_info = 2;
  const static int type_info = 3;
  const static int class_id = 4;
  const static int packed_size = 5;
  const static int building = 6;
}
namespace CompiledCode {
  const static int header = 0;
  const static int metadata = 1;
  const static int name = 2;
  const static int iseq = 3;
  const static int stack_size = 4;
  const static int local_count = 5;
  const static int required_args = 6;
  const static int post_args = 7;
  const static int total_args = 8;
  const static int splat = 9;
  const static int lines = 10;
  const static int local_names = 11;
  const static int file = 12;
  const static int scope = 13;
  const static int breakpoints = 14;
  const static int backend_method = 15;
  const static int jit_data = 16;
  const static int literals = 17;
}
namespace Dispatch {
  const static int name = 0;
  const static int module = 1;
  const static int method = 2;
  const static int method_missing = 3;
}
namespace Executable {
  const static int header = 0;
  const static int primitive = 1;
  const static int serial = 2;
  const static int execute = 3;
  const static int prim_index = 4;
  const static int inliners = 5;
}
namespace Float {
  const static int header = 0;
  const static int val = 1;
}
namespace HeaderWord {
  const static int flags64 = 0;
}
namespace InlineCache {
  const static int name = 0;
  const static int cache = 1;
  const static int call_unit = 2;
  const static int initial = 3;
  const static int execute = 4;
  const static int seen_classes_overflow = 5;
}
namespace InlineCacheHit {
  const static int entry = 0;
  const static int hits = 1;
}
namespace MethodCacheEntry {
  const static int header = 0;
  const static int stored_module = 1;
  const static int receiver_class = 2;
  const static int method = 3;
}
namespace Module {
  const static int header = 0;
  const static int method_table = 1;
  const static int module_name = 2;
  const static int constants = 3;
  const static int superclass = 4;
  const static int seen_ivars = 5;
  const static int mirror = 6;
}
namespace Numeric {
  const static int header = 0;
}
namespace Object {
  const static int header = 0;
}
namespace ObjectFlags {
  const static int flags = 0;
  const static int aux_word = 1;
}
namespace ObjectHeader {
  const static int header = 0;
  const static int klass = 1;
  const static int ivars = 2;
  const static int body = 3;
}
namespace Proc {
  const static int block = 0;
  const static int lambda = 1;
  const static int bound_method = 2;
}
namespace StackVariables {
  const static int on_heap = 0;
  const static int parent = 1;
  const static int block = 2;
  const static int module = 3;
  const static int last_match = 4;
  const static int locals = 5;
}
namespace State {
  const static int vm = 0;
  const static int vm_jit = 1;
  const static int shared = 2;
}
namespace Tuple {
  const static int header = 0;
  const static int full_size = 1;
  const static int field = 2;
}
namespace UnwindInfo {
  const static int target_ip = 0;
  const static int stack_depth = 1;
  const static int type = 2;
}
namespace VMJIT {
  const static int stack_start = 0;
  const static int stack_limit = 1;
  const static int stack_size = 2;
  const static int interrupt_with_signal = 3;
  const static int interrupt_by_kill = 4;
  const static int check_local_interrupts = 5;
  const static int thread_step = 6;
}
namespace VariableScope {
  const static int header = 0;
  const static int block = 1;
  const static int method = 2;
  const static int module = 3;
  const static int parent = 4;
  const static int heap_locals = 5;
  const static int last_match = 6;
  const static int self = 7;
  const static int number_of_locals = 8;
  const static int isolated = 9;
  const static int locals = 10;
  const static int block_as_method = 11;
}
namespace jit_RuntimeData {
  const static int method = 0;
  const static int name = 1;
  const static int module = 2;
}
}
#endif
