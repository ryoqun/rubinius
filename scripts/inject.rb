require 'awesome_print'
gem 'ruby-graphviz'
require 'graphviz'

require 'graphviz'

module Rubinius
  class Optimizer
    class OpRand
      attr_reader :bytecode
      def initialize(bytecode)
        @bytecode = bytecode
      end
    end

    class JumpLabel < OpRand
      attr_reader :target
      def initialize(bytecode, inst)
        super(bytecode)
        @target = inst
      end
    end

    class Count < OpRand
      def to_i
        bytecode
      end
    end

    class Literal < OpRand
      def to_label(optimizer)
        "<literal: #{(optimizer.compiled_code.literals[bytecode] || bytecode).to_s[0, 20]}>"
      end
    end

    class Serial < OpRand
    end

    class Local < OpRand
      def to_label(optimizer)
        "<local: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
    end

    class Inst
      attr_reader :instruction, :imports, :exports
      attr_accessor :op_rands
      def initialize(instruction)
        @instruction = instruction
        @op_rands = nil
        @jump_targets = []
        @imports = []
        @exports = []
      end

      def op_code
        @instruction.instruction.opcode
      end

      def control_flow
        @instruction.instruction.control_flow
      end

      def to_label(optimizer)
        instruction.to_s
      end

      def jump_target
        raise "no" unless control_flow == :branch
        @op_rands.first.target
      end

      def stack_produced
        count = instruction.instruction.stack_produced

        case op_code
        when :move_down
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
        when :move_down
          0
        else
          count
        end
      end
    end

    class JumpTarget
    end

    attr_reader :compiled_code, :instructions, :data_flows
    def initialize(compiled_code)
      @compiled_code = compiled_code
      @passes = []
      @data_flows = []
      decode
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
        #ap inst
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
            Count.new(bytecode)
          when :local
            Local.new(bytecode)
          when :location
            JumpLabel.new(bytecode, ip_to_inst[bytecode])
          when :literal
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
    end

    def encode
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

      class Argument
        attr_reader :instruction
        def initialize(index, instruction)
          @index = index
          @instruction = instruction
        end

        def to_label(_optimizer)
          "arg#{@index}"
        end
      end

      attr :source, :sink
      def initialize(source, sink)
        @source = source
        @sink = sink
      end
    end

    class DataFlowAnalyzer < Analysis
      def optimize
        stack = []
        optimizer.instructions.each do |instruction|
          case instruction.op_code
          when :push_self
            optimizer.data_flows.push(DataFlow.new(DataFlow::Self.new, instruction))
          when :push_local, :push_literal, :push_const_fast
            instruction.op_rands.each do |op_rand|
              optimizer.data_flows.push(DataFlow.new(op_rand, instruction))
            end
          when :set_local, :set_literal, :set_const_fast
            instruction.op_rands.each do |op_rand|
              optimizer.data_flows.push(DataFlow.new(instruction, op_rand))
            end
          when :pop
            optimizer.data_flows.push(DataFlow.new(instruction, DataFlow::Void.new))
          when :ret
            optimizer.data_flows.push(DataFlow.new(instruction, DataFlow::Exit.new))
          end

          case instruction.op_code
          when :send_stack
            instruction.stack_consumed.times.to_a.reverse.each do |index|
              if index.zero?
                source = stack.pop
                receiver = DataFlow::Receiver.new(instruction)
                instruction.imports.unshift(receiver)
                optimizer.data_flows.push(DataFlow.new(source, receiver))
              else
                source = stack.pop
                arg = DataFlow::Argument.new(index, instruction)
                instruction.imports.unshift(arg)
                optimizer.data_flows.push(DataFlow.new(source, arg))
              end
            end
          else
            puts
            p instruction
            instruction.stack_consumed.times do
              optimizer.data_flows.push(DataFlow.new(stack.pop, instruction))
            end
          end
          puts
          p instruction
          instruction.stack_produced.times do
            stack.push(instruction)
          end
        end
      end
    end

    class DataFlowPrinter < Analysis
      def optimize
        @g = GraphViz.new(:G, :type => :digraph)

        optimizer.data_flows.each do |data_flow|
          source_node = decorate_node(data_flow.source)

          if data_flow.sink.is_a?(DataFlow::Argument) or data_flow.sink.is_a?(DataFlow::Receiver)
            sink_node = decorate_node(data_flow.sink.instruction)
            edge = @g.add_edges(source_node, {sink_node => data_flow.sink.to_label(optimizer)})
          else
            sink_node = decorate_node(data_flow.sink)
            edge = @g.add_edges(source_node, sink_node)
          end
        end

        @g.output(:pdf => "data_flow.pdf")
      end

      def escape(text)
        text.gsub(/</, "\\<").gsub(/>/, "\\>")
      end

      def decorate_node(data)
        if data.is_a?(Inst) and not data.imports.empty?
          node = @g.add_nodes(data.to_label(optimizer))
          label = escape(data.to_label(optimizer))
          imports = data.imports.collect { |import| "<#{import.to_label(optimizer)}>#{escape(import.to_label(optimizer))}" }.join("|")
          node.label = "{{#{imports}}|#{label}}"
          node.shape = 'record'
        else
          node = @g.add_nodes(data.to_label(optimizer))
          node.shape = 'rect'
        end
        node
      end
    end

    class CFGPrinter < Analysis
      def optimize
        g = GraphViz.new(:G, :type => :digraph)

        previous = nil
        optimizer.instructions.each do |instruction|
          label = instruction.instruction.to_s

          g.add_nodes(label)
          node = g.get_node(label)
          node.shape = 'rect'
          if previous
            previous_label = previous.instruction.to_s
            g.add_edges(previous_label, label)
          end
          if instruction.control_flow == :branch
            g.add_edges(label, instruction.jump_target.instruction.to_s)
          end
          previous = instruction
        end


        g.output(:pdf => "hello_world2.pdf")
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

code = "".method(:[]).executable
opt = Rubinius::Optimizer.new(code)
opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
opt.add_pass(Rubinius::Optimizer::CFGPrinter)
opt.add_pass(Rubinius::Optimizer::DataFlowPrinter)
opt.run
puts code.decode

return
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
