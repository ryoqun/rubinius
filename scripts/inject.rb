require 'awesome_print'
require 'graphviz'

require 'graphviz'

module Rubinius
  class Optimizer
    class OpRand
      attr_reader :bytecode
      def initialize(bytecode)
        @bytecode = bytecode
      end

      def ==(other)
        other.is_a?(self.class) and other.bytecode == bytecode
      end
    end

    class JumpLabel < OpRand
      attr_accessor :target
      def initialize(bytecode, inst)
        super(bytecode)
        @target = inst
      end

      def to_label(_optimizer)
        @target.to_label(_optimizer)
      end

      def to_bytecode
        @target.ip
      end
    end

    class Count < OpRand
      def to_i
        bytecode
      end
      alias_method :to_bytecode, :to_i
    end

    module Endpoint
    end

    class Literal < OpRand
      include Endpoint
      def to_label(optimizer)
        "<literal: #{(optimizer.compiled_code.literals[bytecode] || bytecode).inspect.to_s[0, 20]}>"
      end

      alias_method :to_bytecode, :bytecode
    end

    class Serial < OpRand
      alias_method :to_bytecode, :bytecode
    end

    class Local < OpRand
      def to_label(optimizer)
        "<local: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
      alias_method :to_bytecode, :bytecode
    end

    class Parameter < OpRand
      def to_label(optimizer)
        "<param: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
      alias_method :to_bytecode, :bytecode
    end

    class StackLocal < OpRand
      def to_label(optimizer)
        "<stk_local: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
      alias_method :to_bytecode, :bytecode
    end

    class Type < OpRand
      def to_label(optimizer)
        "type"
      end
      alias_method :to_bytecode, :bytecode
    end

    class Inst
      attr_reader :instruction, :imports, :exports, :jump_targets
      attr_accessor :op_rands, :previous, :next, :ip
      def initialize(instruction)
        @instruction = instruction
        @op_rands = nil

        @previous = @next = nil
        @jump_targets = []

        @imports = []
        @exports = []

        @ip = 0
      end

      def remove
        self.previous.next = self.next
        self.jump_targets.each do |jump_target|
          jump_target.op_rands.each do |op_rand|
            if op_rand.is_a?(JumpLabel)
              op_rand.target = self.next
            end
          end
        end
        self.next.jump_targets.concat(self.jump_targets)
      end

      def op_code
        @instruction.instruction.opcode
      end

      def bytecode
        @instruction.instruction.bytecode
      end

      def instruction_width
        @instruction.instruction.width
      end

      def control_flow_type
        @instruction.instruction.control_flow
      end

      def to_label(optimizer)
        instruction.to_s
      end

      def jump_target
        raise "no #{op_code} #{self.inspect}" unless control_flow_type == :branch or control_flow_type == :handler
        @op_rands.first.target
      end

      def stack_produced
        count = instruction.instruction.stack_produced

        case op_code
        when :move_down
          op_rands[count.last - 1].to_i
        when :ret, :goto, :reraise
          0
        else
          count
        end
      end

      def stack_consumed
        count = instruction.instruction.stack_consumed

        case op_code
        when :send_stack
          count.first + op_rands[count.last - 1].to_i
        when :send_stack_with_block, :yield_stack
          count.first + op_rands[count.last - 1].to_i
        when :string_build, :make_array
          count.first + op_rands.first.to_i
        when :move_down
          op_rands[count.last - 1].to_i
        else
          count
        end
      end
    end

    class JumpTarget
    end

    attr_reader :compiled_code, :instructions, :control_flows, :data_flows
    def initialize(compiled_code)
      @compiled_code = compiled_code
      @passes = []
      @control_flows = []
      @data_flows = []
      decode
    end

    def remove(removed_inst)
      removed_inst.remove
      @instructions.reject! {|inst| inst.equal?(removed_inst)}
    end

    def unlink(from, to)
      #removed_inst.remove
      #@instructions.reject! {|inst| inst.equal?(removed_inst)}
      #if from.next == to
      #  from.next = to.next
      #elsif from.jump_target == to
      #  from.jump_target = to.next
      #else
      #  raise "aa"
      #end
      @control_flows.each do |control_flow|
        if control_flow.from.equal?(from) and
           control_flow.to.equal?(to)
          #p :fffound
          #p from.to_label(self)
          #p to.to_label(self)
          control_flow.remove
        end
      end
    end

    def add_data_flow(data_flow)
      data_flow.install
      @data_flows.push(data_flow)
    end

    def add_control_flow(control_flow)
      control_flow.install
      @control_flows.push(control_flow)
    end

    def add_pass(pass, *args)
      @passes << pass.new(self, *args)
    end

    def decode
      ip_to_inst = {}
      ip = 0
      @instructions = Rubinius::InstructionDecoder.new(@compiled_code.iseq).
                                                   decode.
                                                   collect do |stream|
        instruction = CompiledCode::Instruction.new(stream, @compiled_code, ip)
        op_code, *bytecodes = stream

        inst = ip_to_inst[ip] = Inst.new(instruction)
        ip += instruction.size
       # ap inst.to_label(self)
        inst
      end
      #ap ip_to_inst

      ip = 0
      Rubinius::InstructionDecoder.new(@compiled_code.iseq).
                                   decode.
                                   each do |stream|
        inst = ip_to_inst[ip]
        op_code, *bytecodes = stream
        op_rands = inst.instruction.args.collect.with_index do |arg, index|
          bytecode = bytecodes[index]
          case op_code.args[index]
          when :count, :positions, :index
            if inst.op_code == :passed_arg
              Parameter.new(bytecode)
            else
              Count.new(bytecode)
            end
          when :local
            Local.new(bytecode)
          when :which
            StackLocal.new(bytecode)
          when :type
            Type.new(bytecode)
          when :location, :ip
            label = JumpLabel.new(bytecode, ip_to_inst[bytecode])
            ip_to_inst[bytecode].jump_targets.push(inst)
            label
          when :literal, :number
            Literal.new(bytecode)
          when :serial
            Serial.new(bytecode)
          else
            raise "unsupported: #{op_code.args[index].inspect}"
          end
          #p bytecodes[index]
          #p op_code.args[index]
          #p arg.class
        end
        inst.op_rands = op_rands
        ip += inst.instruction.size
        #p op_rands
      end
    end

    def run
      @passes.each(&:optimize)
      encode
    end

    def rerun(klass) 
      @passes.each do |pass|
        if pass.is_a?(klass)
          pass.reset
          pass.optimize
        end
      end
    end

    def encode
      ip = 0
      @instructions.each do |inst|
        inst.ip = ip
        ip += inst.instruction_width
      end

      bytecodes = []
      @instructions.each do |inst|
        bytecodes << inst.bytecode  
        inst.op_rands.each do |op_rand|
          bytecodes << op_rand.to_bytecode
        end
      end

      p bytecodes

      opted = OptimizedCode.new
      opted.iseq = Rubinius::InstructionSequence.new(bytecodes.to_tuple)
      opted.literals = @compiled_code.literals
      opted.lines = [-1, 999, 0, 999, 9999].to_tuple
      opted.required_args = @compiled_code.required_args
      opted.post_args = @compiled_code.post_args
      opted.total_args = @compiled_code.total_args
      opted.splat = @compiled_code.splat
      opted.block_index = @compiled_code.block_index
      opted.stack_size = @compiled_code.stack_size
      opted.local_count = @compiled_code.local_count
      opted.name = :"_Z_#{@compiled_code.name}_#{bytecodes.size}"
      opted.local_names = @compiled_code.local_names
      opted.original_code = @compiled_code
      opted
    end

    class Optimization
      attr_reader :optimizer
      def initialize(optimizer)
        @optimizer = optimizer
      end

      def optimize
        raise
      end

      def deoptimize
        raise
      end
    end

    class Analysis < Optimization
      def deoptimize
      end
    end

    class DataFlow
      class Self
        def to_label(optimizer)
          "<self>"
        end
      end

      class Exit
        def to_label(optimizer)
          "<exit>"
        end
      end

      class Void
        def to_label(optimizer)
          "<void>"
        end
      end

      class Receiver
        attr_reader :instruction
        def initialize(instruction)
          @instruction = instruction
        end

        def to_label(optimizer)
          "recv"
        end
      end

      class Block
        attr_reader :instruction
        def initialize(instruction)
          @instruction = instruction
        end

        def to_label(optimizer)
          "block"
        end
      end

      class Object
        attr_reader :instruction
        def initialize(instruction)
          @instruction = instruction
        end

        def to_label(optimizer)
          "object"
        end
      end

      class Class
        attr_reader :instruction
        def initialize(instruction)
          @instruction = instruction
        end

        def to_label(optimizer)
          "class"
        end
      end

      class Argument
        attr_reader :instruction
        def initialize(index, instruction)
          @index = index
          @instruction = instruction
        end

        def to_label(_optimizer)
          "arg#{@index - 1}"
        end
      end

      class Shuffle
        attr_reader :instruction
        def initialize(index, instruction)
          @index = index
          @instruction = instruction
        end

        def to_label(_optimizer)
          "port#{@index}"
        end
      end

      attr :source, :sink
      def initialize(source, sink)
        @source = source
        @sink = sink
      end

      def install
      end
    end

    class DataFlowAnalyzer < Analysis
      def optimize
        goto_to_stack = {}
        main_stack = []
        stacks = [main_stack]
        previous = nil
        optimizer.instructions.each do |instruction|
          #p instruction.to_label(optimizer)
          jump_target_found = false
          instruction.jump_targets.each do |goto|
            if goto.op_code == :goto or
               goto.op_code == :goto_if_true or
               goto.op_code == :goto_if_false
              jump_target_found = true
              stacks << goto_to_stack[goto] if goto_to_stack.has_key?(goto)
            end
          end
          if not previous.nil? and (previous.op_code == :goto or previous.op_code == :ret)
            stacks.reject!{|s| s.equal?(main_stack)}
            if not jump_target_found and stacks.all?(&:empty?)
              previous = instruction
              next
            end
          end

          stacks.last(stacks.size - 1).each do |other_stack|
            stacks.delete(other_stack) if other_stack.empty?
          end

          if stacks.empty?
            main_stack = []
            stacks = [main_stack]
          end
          stacks.uniq!
          stacks.each.with_index do |stack, stack_index|
            case instruction.op_code
            when :goto_if_true, :goto_if_false, :goto
              stk = stack.dup
              if instruction.op_code != :goto
                raise "underflow" if stk.empty?
                stk.pop
                #p instruction
                #ap stk, raw: true
              else
                #p stk.map{|a| a.to_label(optimizer) }
              end
              goto_to_stack[instruction] = stk unless stk.empty?
            when :push_self
              optimizer.add_data_flow(DataFlow.new(DataFlow::Self.new, instruction))
            when :push_local, :push_literal, :push_const_fast, :push_ivar, :find_const_fast, :passed_arg
              instruction.op_rands.each do |op_rand|
                optimizer.add_data_flow(DataFlow.new(op_rand, instruction))
              end
            when :set_local, :set_literal, :set_const_fast, :set_ivar
              instruction.op_rands.each do |op_rand|
                optimizer.add_data_flow(DataFlow.new(instruction, op_rand))
              end
            when :pop
              #optimizer.add_data_flow(DataFlow.new(instruction, DataFlow::Void.new))
            when :ret
              #optimizer.add_data_flow(DataFlow.new(instruction, DataFlow::Exit.new))
            end

            case instruction.op_code
            when :send_stack
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                if index.zero?
                  source = stack.pop
                  receiver = DataFlow::Receiver.new(instruction)
                  instruction.imports.unshift(receiver) if stack_index.zero?
                  optimizer.add_data_flow(DataFlow.new(source, receiver))
                else
                  source = stack.pop
                  arg = DataFlow::Argument.new(index, instruction)
                  instruction.imports.unshift(arg) if stack_index.zero?
                  optimizer.add_data_flow(DataFlow.new(source, arg))
                end
              end
            when :swap_stack
              source = stack.pop
              shuffle1 = DataFlow::Shuffle.new(1, instruction)
              optimizer.add_data_flow(DataFlow.new(source, shuffle1))

              source = stack.pop
              shuffle2 = DataFlow::Shuffle.new(0, instruction)
              optimizer.add_data_flow(DataFlow.new(source, shuffle2))

              instruction.imports.unshift(shuffle1) if stack_index.zero?
              instruction.imports.unshift(shuffle2) if stack_index.zero?
            when :kind_of
              source = stack.pop
              shuffle = DataFlow::Class.new(instruction)
              instruction.imports.unshift(shuffle) if stack_index.zero?
              optimizer.add_data_flow(DataFlow.new(source, shuffle))

              source = stack.pop
              shuffle = DataFlow::Object.new(instruction)
              instruction.imports.unshift(shuffle) if stack_index.zero?
              optimizer.add_data_flow(DataFlow.new(source, shuffle))
            when :move_down
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                source = stack.pop
                shuffle = DataFlow::Shuffle.new(index, instruction)
                instruction.imports.unshift(shuffle) if stack_index.zero?
                optimizer.add_data_flow(DataFlow.new(source, shuffle))
              end
            when :send_stack_with_block
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                if index == 0
                  source = stack.pop
                  receiver = DataFlow::Receiver.new(instruction)
                  instruction.imports.unshift(receiver) if stack_index.zero?
                  optimizer.add_data_flow(DataFlow.new(source, receiver))
                elsif index == 1
                  source = stack.pop
                  receiver = DataFlow::Block.new(instruction)
                  instruction.imports.unshift(receiver) if stack_index.zero?
                  optimizer.add_data_flow(DataFlow.new(source, receiver))
                else
                  source = stack.pop
                  arg = DataFlow::Argument.new(index, instruction)
                  instruction.imports.unshift(arg) if stack_index.zero?
                  optimizer.add_data_flow(DataFlow.new(source, arg))
                end
              end
            else
              #puts
              #p instruction
              instruction.stack_consumed.times do
                optimizer.add_data_flow(DataFlow.new(stack.pop, instruction))
              end
            end
            #puts
            #p instruction
            #p instruction.stack_produced
            #  p instruction.op_code
            if instruction.op_code == :move_down
              exports = []
              instruction.stack_produced.times.to_a.rotate(-1).each do |index|
                shuffle = DataFlow::Shuffle.new(index, instruction)
                exports[index] = shuffle
                stack.push(shuffle)
              end
              #p exports.size
              exports.size.times.to_a.reverse.each do |index|
                instruction.exports.unshift DataFlow::Shuffle.new(index, instruction) if stack_index.zero?
                #instruction.exports.unshift(export)
              end
            else
              instruction.stack_produced.times.to_a.reverse.each do |index|
                if instruction.op_code == :swap_stack
                  shuffle = DataFlow::Shuffle.new(index, instruction)
                  instruction.exports.unshift(shuffle) if stack_index.zero?
                  stack.push(shuffle)
                else
                  stack.push(instruction)
                end
              end
            end
          end
          previous = instruction
        end
      end
    end

    class DataFlowPrinter < Analysis
      def optimize
        @g = GraphViz.new(:G, :type => :digraph)
        @g[:rankdir] = "LR"
        flags = {}

        optimizer.data_flows.each do |data_flow|
          if data_flow.sink.is_a?(DataFlow::Argument) or
             data_flow.sink.is_a?(DataFlow::Receiver) or
             data_flow.sink.is_a?(DataFlow::Block) or
             data_flow.sink.is_a?(DataFlow::Shuffle) or
             data_flow.sink.is_a?(DataFlow::Object) or
             data_flow.sink.is_a?(DataFlow::Class)
            sink_node = decorate_node(data_flow.sink.instruction)
            sink_node = {sink_node => data_flow.sink.to_label(optimizer)}
          else
            sink_node = decorate_node(data_flow.sink)
          end

          if data_flow.source.is_a?(DataFlow::Shuffle)
            source_node = decorate_node(data_flow.source.instruction)
            source_node = {source_node => data_flow.source.to_label(optimizer)}
          else
            source_node = decorate_node(data_flow.source)
          end

          flag_key = [source_node, sink_node]
          flags[flag_key] || @g.add_edges(source_node, sink_node)
          flags[flag_key] = true
        end

        @g.output(:pdf => "data_flow.pdf")
      end

      def escape(text)
        text.gsub(/</, "\\<").gsub(/>/, "\\>")
      end

      def decorate_node(data)
        suffix = nil #"(jump_target)" if data.respond_to?(:jump_targets) and not data.jump_targets.empty?
        if data.is_a?(Inst) and (not data.imports.empty? or not data.exports.empty?)
          node = @g.get_node(data.to_label(optimizer)) || @g.add_nodes(data.to_label(optimizer))
          label = escape(data.to_label(optimizer))

          imports = data.imports.collect do |import|
             if import.is_a?(DataFlow::Shuffle)
               port = "#{import.to_label(optimizer)}i"
             else
               port = import.to_label(optimizer)
            end
            "<#{port}>#{escape(import.to_label(optimizer))}"
          end.join("|")
          imports = "{#{imports}}|" unless imports.empty?

          exports = data.exports.collect do |export|
            if export.is_a?(DataFlow::Shuffle)
              port = "#{export.to_label(optimizer)}o"
            else
              port = export.to_label(optimizer)
            end
            "<#{port}>#{escape(export.to_label(optimizer))}"
          end.join("|")
          exports = "|{#{exports}}" unless exports.empty?

          node.label = "{#{imports}#{label}#{suffix}#{exports}}"
          node.shape = 'record'
          node.fontname = 'M+ 1mn'
        else
          node = @g.get_node(label = data.to_label(optimizer)) || @g.add_nodes(label = data.to_label(optimizer))
          node.label = "#{label}#{suffix}"

          if data.is_a?(Endpoint)
            node.shape = 'rect'
          else
            node.shape = 'round'
          end

          node.fontname = 'M+ 1mn'
        end
        node
      end
    end

    class ControlFlow
      attr_reader :from, :to
      def initialize(from, to)
        @from = from
        @to = to
        @remove = false
      end

      def remove
        @remove = true
      end

      def removed?
        @remove
      end
    end

    class NextControlFlow < ControlFlow
      def type
        :next
      end

      def install
        @from.next = @to
        @to.previous = @from
      end
    end

    class BranchControlFlow < ControlFlow
      def type
        :branch
      end

      def install
      end
    end

    class ControlFlowAnalysis < Analysis
      def reset
        optimizer.control_flows.clear
      end

      def optimize
        reset
        previous = nil
        optimizer.instructions.each do |instruction|
          if previous and
             previous.op_code != :goto and
             previous.op_code != :ret and
             previous.op_code != :reraise
            optimizer.add_control_flow(NextControlFlow.new(previous, instruction))
          end
          if instruction.control_flow_type == :branch or
             instruction.control_flow_type == :handler
            optimizer.add_control_flow(BranchControlFlow.new(instruction, instruction.jump_target))
          end
          previous = instruction
        end
      end
    end

    class ControlFlowPrinter < Analysis
      def optimize
        g = GraphViz.new(:G, :type => :digraph)
        g[:fontname] = "M+ 1mn"

        entry_node = g.add_nodes(optimizer.compiled_code.inspect);
        label = optimizer.instructions.first.instruction.to_s
        first_instruction_node = g.add_nodes(label)
        g.add_edges(entry_node, first_instruction_node)

        optimizer.control_flows.each do |control_flow|
          node1 = g.add_nodes(control_flow.from.to_label(optimizer))
          node1.shape = 'rect'
          node1.fontname = 'M+ 1mn'
          node2 = g.add_nodes(control_flow.to.to_label(optimizer))
          node2.shape = 'rect'
          node2.fontname = 'M+ 1mn'
          edge = g.add_edges(node1, node2)
          edge.style = 'dotted' if control_flow.removed?
        end

        g.output(:pdf => "cfg.pdf")
      end
    end

    class Entry
      def to_label(optimizer)
        :entry
      end
    end

    class Terminate
      def to_label(optimizer)
        :terminate
      end
    end

    class Save
      def to_label(optimizer)
        :save
      end
    end

    class Restore
      def to_label(optimizer)
        :restore
      end
    end

    class TransformState
    end

    class Matcher
      class << self
        attr_reader :selector, :translator
        def before(selector)
          @selector = selector
        end

        def after(translator)
          @translator = translator
        end
      end

      def initialize(optimizer, scalar)
        @optimizer= optimizer
        @scalar = scalar
        @cursor = nil
      end

      def feed(previous, inst)
        if @cursor.nil?
          @cursor = 0
          @selector = self.class.selector.dup
          @place_holders = {}
          @results = []
        end
        matcher = @selector[@cursor]
        advance = match(inst, matcher)
        if advance.nil? and matcher.is_a?(Symbol)
          @cursor += 1
          matcher = @selector[@cursor]
          advance = match(inst, matcher)
        end

        if advance.nil?
          @cursor = nil
        else
          @cursor += advance
          @results << [previous, inst, matcher]

          if @selector[@cursor].nil?
            @cursor = nil
            return translate
          end
        end

        false
      end

      def match(inst, matcher)
        if matcher.is_a?(Symbol)
          meta_matcher = matcher
          case meta_matcher
          when :no_stack_changes
            if inst.op_code == :check_interrupts or
               inst.op_code == :goto
              0
            else
              nil
            end
          else
            raise
          end
        else
          op_code, *args = matcher
          if inst.op_code == op_code
            ok = true
            args.each.with_index do |arg, index|
              op_rand = inst.op_rands[index]
              if arg.is_a?(Symbol)
                if not @place_holders.has_key?(arg)
                  @place_holders[arg] = op_rand
                else
                  ok = (@place_holders[arg] == op_rand)
                end
              else
                raise "aaaa"
              end
            end
            1 if ok
          else
            nil
          end
        end
      end

      def translate
        p @results.map(&:last)
        @results.each do |prev, cur, match|
          unless self.class.translator.include?(match)
            @scalar.remove(prev, cur)
          end
        end

        false
      end
    end

    class PushRemover < Matcher
      before [
        [:set_local, :local0],
        [:pop],
        :no_stack_changes,
        [:push_local, :local0],
      ]

      after [
        [:set_local, :local0],
        :no_stack_changes,
      ]
    end

    class NilRemover < Matcher
      before [
        [:push_nil],
        [:pop],
      ]

      after [
      ]
    end

    class InfiniteLoop < Matcher
      before [
        [:push_true],
        [:goto_if_false],
      ]

      after [
      ]
    end

    class Prune < Optimization
      def optimize
        incoming_flows = {
          optimizer.instructions.first => [],
        }
        optimizer.control_flows.each do |control_flow|
          incoming_flows[control_flow.to] ||= []
          incoming_flows[control_flow.to] << control_flow
        end
        unused_insts = []
        optimizer.instructions.each do |inst|
          if not incoming_flows[inst].empty? and incoming_flows[inst].all?(&:removed?)
            #p :remove
            #p inst.to_label(optimizer)
            #p :remove_done
            unused_insts << inst
          end
        end
        unused_insts.each do |inst|
          optimizer.remove(inst)
        end
        #puts
      end
    end

    class ScalarTransform < Optimization
      def optimize
        transformed = true

        while transformed
          #puts "pass: #{count}"
          transformed = false
          scalar_each do |event|
            case event
            when Entry, Restore
              reset
            when Save, Terminate
            else
              transformed ||= feed(event)
            end
          end
        end
      end

      def reset
        @states = [
          PushRemover.new(optimizer, self),
          NilRemover.new(optimizer, self),
          InfiniteLoop.new(optimizer, self),
        ]
      end

      def feed(event)
        @states.each do |state|
          state.feed(*event)
        end

        false
      end

      def remove(previous, inst)
        #puts
        #puts "aaaa"
        #p previous.to_label(optimizer)
        #p inst.to_label(optimizer)
        #puts "zzzzz"
        optimizer.unlink(previous, inst)
      end

      def scalar_each
        entry = optimizer.instructions.first
        stack = [[nil, entry]]
        loop_marks = {}

        yield Entry.new
        first = true
        until stack.empty?
          previous, current = stack.pop
          if first
            first = false
          else
            yield Restore.new
          end
          while current
            if current.control_flow_type == :branch
              if loop_marks[current].nil?
                loop_marks[current] = true
                if current.next
                  yield Save.new
                  stack.push([current, current.next])
                  stack.push([current, current.jump_target])
                  yield [previous, current]
                  current = nil
                else
                  previous = current
                  current = current.jump_target
                end
              else
                current = nil
              end
            elsif current.control_flow_type == :return
              break
            else
              yield [previous, current]
              previous = current
              current = current.next
            end
          end
        end
        yield Terminate.new
      end
    end

    class Inliner < Optimization
      attr_reader :container, :inlined
      def initialize(container, inlined)
        @container = container
        @inlined = inlined
      end

      def optimize
      end
    end
  end
end

#code = Rubinius::Optimizer::Inst.instance_method(:stack_consumed).executable
#code = File.method(:absolute_path).executable
def loo
  i = 0
  while i < 40_000_000
    "aaa" + "bbbb"
    i += 1
  end
end
#code = Array.instance_method(:set_index).executable
#code = method(:loo).executable
#code = "".method(:dump).executable
#code = "".method(:[]).executable
#code = "".method(:start_with?).executable
code = [].method(:cycle).executable
opt = Rubinius::Optimizer.new(code)
opt.add_pass(Rubinius::Optimizer::ControlFlowAnalysis)
opt.add_pass(Rubinius::Optimizer::ScalarTransform)
#opt.add_pass(Rubinius::Optimizer::Prune)
#opt.add_pass(Rubinius::Optimizer::ControlFlowAnalysis)
opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)

opt.add_pass(Rubinius::Optimizer::ControlFlowPrinter)
opt.add_pass(Rubinius::Optimizer::DataFlowPrinter)

optimized_code = opt.run

#opt = Rubinius::Optimizer.new(code)
#opt.add_pass(Rubinius::Optimizer::ControlFlowAnalysis)
##opt.add_pass(Rubinius::Optimizer::ScalarTransform)
#opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
#
#opt.add_pass(Rubinius::Optimizer::ControlFlowPrinter)
#opt.add_pass(Rubinius::Optimizer::DataFlowPrinter)
#
#un_code = opt.run

#puts un_code.decode
puts optimized_code.decode

return
def measure
  started_at = Time.now
  yield
  puts Time.now - started_at
end
# invoke(@name, @defined_in, obj, args, block)
10.times do
  puts optimized_code.decode.size
  measure do
    optimized_code.invoke(:loo_optimized, self.class, self, [], nil)
  end
  puts un_code.decode.size
  measure do
    un_code.invoke(:loo, self.class, self, [], nil)
  end
end
#puts code.decode
#puts
#puts code.decode

def foo
  "aaa" + "bbbb"
end

def hello
  code = Rubinius::OptimizedCode.new
  stream = Rubinius::Tuple.new(2)
  stream[0] = 1
  stream[1] = 11
  code.iseq = Rubinius::InstructionSequence.new(stream)
  li = Rubinius::Tuple.new(1)
  li[0] = "hello yay!!!!!!!!!!"
  code.literals = li
  code.lines = Rubinius::Tuple.new(0)
  code.required_args = 1
  code.post_args = 0
  code.total_args = 1
  code.splat = nil
  code.block_index = nil
  code.stack_size = 1
  code.local_count    = 1
  code.name = :foo_optimizeddd
  code.lines = [-1, 555, 0, 555, 2].to_tuple
  #code.original_code = String.instance_method(:+).executable
  code.original_code = "".method(:+).executable.call_sites.first.executable
  code.guards = [Rubinius::Guard.new(:self, "")].to_tuple
  p code.invoke(:foo_optimized, String, "", [3], nil)

  100.times do
    foo
  end

  pp method(:foo).executable.call_sites.to_a

  c = method(:foo).executable.call_sites.first
  optimized_callsite = Rubinius::OptimizedCallSite.new(c, code)
  p optimized_callsite.optimized_code.original_code
  p optimized_callsite.optimized_code

  t = Time.now
  1000000.times do
    foo
  end
  p Time.now - t
  pp "".method(:foo).executable.call_sites.to_a

  optimized_callsite.inject

  p :be_careful!
  t = Time.now
  1000000.times do
    foo
  end
  p Time.now - t

  pp method(:foo).executable.call_sites.to_a

  p foo

  pp method(:foo).executable.call_sites.to_a

  p String.serial_id
  String.class_exec do
    def inspect
      super
    end
  end
  p String.serial_id

  p foo
  pp method(:foo).executable.call_sites.to_a
end

hello

#def aa
#  "aaa" + "bbb"
#end
#
#loop do
#  aa
#end


#guards:
#  :__block__ => (inlined) original CompiledMethod (= def aa)
#  :Rubinius, :Type, :compatible? => (inlined) CompiledMethod
