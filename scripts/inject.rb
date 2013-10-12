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
      attr_reader :instruction
      attr_accessor :op_rands
      def initialize(instruction)
        @instruction = instruction
        @op_rands = nil
        @jump_targets = []
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
        instruction.instruction.stack_produced
      end

      def stack_consumed
        op_code = instruction.instruction
        count = op_code.stack_consumed

        if count.respond_to?(:to_i)
          count
        else
          count.first + op_rands[count.last - 1].to_i
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
        def to_label(optimizer)
          "<receiver>"
        end
      end

      class Argument
        def initialize(index)
          @index = index
        end

        def to_label(_optimizer)
          "<arg#{@index}>"
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
                receiver = DataFlow::Receiver.new
                optimizer.data_flows.push(DataFlow.new(source, receiver))
                optimizer.data_flows.push(DataFlow.new(receiver, instruction))
              else
                source = stack.pop
                arg = DataFlow::Argument.new(index)
                optimizer.data_flows.push(DataFlow.new(source, arg))
                optimizer.data_flows.push(DataFlow.new(arg, instruction))
              end
            end
          else
            instruction.stack_consumed.times do
              optimizer.data_flows.push(DataFlow.new(stack.pop, instruction))
            end
          end
          instruction.stack_produced.times do
            stack.push(instruction)
          end
        end
      end
    end

    class DataFlowPrinter < Analysis
      def optimize
        g = GraphViz.new(:G, :type => :digraph)

        optimizer.data_flows.each do |data_flow|
          source_node = g.add_nodes(data_flow.source.to_label(optimizer))
          source_node.shape = 'rect'

          sink_node = g.add_nodes(data_flow.sink.to_label(optimizer))
          sink_node.shape = 'rect'

          g.add_edges(source_node, sink_node)
        end


        g.output(:pdf => "data_flow.pdf")
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

code = "".method(:StringValue).executable
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
