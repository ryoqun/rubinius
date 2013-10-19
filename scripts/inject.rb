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

      def to_bytecode(instruction)
        @bytecode
      end

      def ==(other)
        other.is_a?(self.class) and other.bytecode == bytecode
      end
    end

    class Count < OpRand
      def to_i
        bytecode
      end
    end

    module Endpoint
    end

    class Literal < OpRand
      include Endpoint
      def to_label(optimizer)
        "<literal: #{(optimizer.compiled_code.literals[bytecode] || bytecode).inspect.to_s[0, 20]}>"
      end
    end

    class Serial < OpRand
    end

    class Local < OpRand
      def to_label(optimizer)
        "<local: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
    end

    class Parameter < OpRand
      def to_label(optimizer)
        "<param: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
    end

    class StackLocal < OpRand
      def to_label(optimizer)
        "<stk_local: #{optimizer.compiled_code.local_names[bytecode] || bytecode}>"
      end
    end

    class Type < OpRand
      def to_label(optimizer)
        "type"
      end
    end

    class Inst
      attr_reader :instruction, :imports, :exports, :branch_flows, :previous, :incoming_flows, :entry_flow
      attr_accessor :op_rands, :next, :ip,
                    :following_instruction, :preceeding_instruction, :unconditional_branch_flow
      def initialize(instruction)
        @instruction = instruction
        @op_rands = nil

        @previous = @next = nil
        @branch_flows = []
        @incoming_flows = []

        @imports = []
        @exports = []

        @following_instruction = @preceeding_instruction = nil
        @entry_control_flow = nil

        @ip = 0
        @generation = 0
        @unconditional_branch_flow = nil
      end

      def unconditional_branch_flow?
        !!@unconditional_branch_flow
      end

      def previous=(prev)
        if prev
          @incoming_flows.delete(@previous) if @previous
          @incoming_flows.push(prev)
          @previous = prev
        else
          @incoming_flows.delete(@previous) if @previous
          @previous = nil
        end
      end

      def static_next_flow
        if op_code == :goto
          branch_flow
        elsif op_code == :ret
          nil
        elsif control_flow_type == :next
          next_flow
        elsif unconditional_branch_flow?
          unconditional_branch_flow
        else
          nil
        end
      end

      def to_s
        instruction.to_s
      end

      def inspect
        instruction.to_s
      end

      def as_entry_inst
        @previous = @entry_flow = EntryControlFlow.new(self)
        self
      end

      def dup
        super.tap do |new|
          new.instance_variable_set(:@generation, @generation + 1)
        end
      end

      def entry_inst?
        !!@entry_flow
      end

      def next_flow
        @next
      end

      def prev_flow
        @previous
      end

      def branch_flows
        @branch_flows
      end

      def raw_remove
        if following_instruction
          following_instruction.preceeding_instruction = preceeding_instruction
        end
        if preceeding_instruction
          preceeding_instruction.following_instruction = following_instruction
        end
      end

      def remove
        raw_remove

        p self.to_label(nil)
        if prev_flow
          p prev_flow.to_label(nil)
          prev_flow.unremove
          prev_flow.point_to_next_instruction
          #p prev_flow.to_label(nil)
        end
        #p branch_flows.map(&:class)
        branch_flows.dup.each do |f|
          while f.next_flow? and f.next_flow.removed?
            p next_flow.to_label(nil)
            f.point_to_next_instruction if f
          end
        end
      end

      def insert_after(inst)
        following_instruction.preceeding_instruction = inst
        inst.following_instruction = following_instruction
        self.following_instruction = inst
        inst.preceeding_instruction = self
      end

      def op_code
        if @instruction
          @instruction.instruction.opcode
        else
          if entry_inst?
            :entry
          else
            raise "no op_code #{self.class}"
          end
        end
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
        if @generation.zero?
          instruction.to_s
        else
          "#{instruction.to_s} (#{@generation})"
        end
      end

      def branch_flow
        raise "no #{op_code} #{self.inspect}" unless control_flow_type == :branch or control_flow_type == :handler
        @op_rands.first
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
    attr_accessor :entry_flow
    def initialize(compiled_code)
      @compiled_code = compiled_code
      @passes = []
      @control_flows = []
      @data_flows = []
      decode
    end

    def remove_control_flow(flow)
      raise "baaad" if flow.nil?
      @control_flows.delete(flow)
    end

    def first_flow
      @entry_flow
    end

    def first_instruction
      @entry_flow.dst
    end

    def unlink(spot, src, dst)
      #removed_inst.remove
      #@instructions.reject! {|inst| inst.equal?(removed_inst)}
      #if src.next == dst
      #  src.next = dst.next
      #elsif src.branch_flow == dst
      #  src.branch_flow = dst.next
      #else
      #  raise "aa"
      #end
      @control_flows.each do |control_flow|
        if control_flow.src.equal?(src) and
           control_flow.dst.equal?(dst)
          #p :fffound
          #p src.to_label(self)
          #p dst.to_label(self)
          control_flow.remove
          control_flow.add_spot(spot)
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
      control_flow
    end

    def add_pass(pass, *args)
      @passes << pass.new(self, *args)
    end

    def decode
      ip_to_inst = {}
      ip = 0
      inst = previous = nil
      Rubinius::InstructionDecoder.new(@compiled_code.iseq).
                                       decode.
                                       collect do |stream|
        instruction = CompiledCode::Instruction.new(stream, @compiled_code, ip)
        op_code, *bytecodes = stream

        inst = ip_to_inst[ip] = Inst.new(instruction)
        if previous
          previous.following_instruction = inst
          inst.preceeding_instruction = previous
        else
          inst.as_entry_inst
          @entry_flow = inst.previous
        end

        ip += instruction.size
        # ap inst.to_label(self)
        previous = inst
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
            BranchControlFlow.new(inst, ip_to_inst[bytecode], bytecode)
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

    def each_instruction
      instruction = first_instruction
      while instruction
        yield instruction
        instruction = instruction.following_instruction
      end
    end

    def encode
      ip = 0
      each_instruction do |inst|
        #p inst.to_label(self)
        inst.ip = ip
        ip += inst.instruction_width
      end

      bytecodes = []
      each_instruction do |inst|
        bytecodes << inst.bytecode
        inst.op_rands.each do |op_rand|
          bytecodes << op_rand.to_bytecode(inst)
        end
      end

      #p bytecodes

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
        optimizer.each_instruction do |instruction|
          #p instruction.to_label(optimizer)
          branch_target_found = false
          instruction.branch_flows.each do |goto|
            if goto.src.op_code == :goto or
               goto.src.op_code == :goto_if_true or
               goto.src.op_code == :goto_if_false
              branch_target_found = true
              stacks << goto_to_stack[goto.src] if goto_to_stack.has_key?(goto.src)
            end
          end
          if not previous.nil? and (previous.op_code == :goto or previous.op_code == :ret)
            stacks.reject!{|s| s.equal?(main_stack)}
            if not branch_target_found and stacks.all?(&:empty?)
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
              #optimizer.add_data_flow(DataFlow.new(DataFlow::Self.new, instruction))
            when :push_local, :push_literal, :push_const_fast, :push_ivar, :find_const_fast, :passed_arg
              #instruction.op_rands.each do |op_rand|
              #  optimizer.add_data_flow(DataFlow.new(op_rand, instruction))
              #end
            when :set_local, :set_literal, :set_const_fast, :set_ivar
              #instruction.op_rands.each do |op_rand|
              #  optimizer.add_data_flow(DataFlow.new(instruction, op_rand))
              #end
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
        suffix = nil #"(branch_flow)" if data.respond_to?(:branch_flows) and not data.branch_flows.empty?
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
      attr_accessor :src, :dst, :spots
      def initialize(src, dst)
        @src = src
        raise "src is nil" if @src.nil?
        @dst = dst
        raise "dst is nil" if @dst.nil?
        @remove = false
        @installed = false
        @spots = []
      end

      def add_spot(spot)
        @spots.push(spot) unless @spots.include?(spot)
      end

      def add_spots(spots)
        @spots.concat(spots).uniq!
      end

      def to_label(optimizer)
        "#{@src.to_label(optimizer).strip}=#{removed? ? "x" : "="}>#{@dst.to_label(optimizer).strip}"
      end

      def static_dst?
        !dynamic_dst?
      end

      def install
        raise "double installation" if @installed
        @installed = true
        self
      end

      def uninstall
        raise "double uninstallation" if not @installed
        @installed = false
        self
      end

      def reinstall
        uninstall

        begin
          yield if block_given?
        ensure
          install
        end
      end

      def remove
        @remove = true
        self
      end

      def unremove
        @remove = false
      end

      def removed?
        @remove
      end

      def next_flow
        if @dst.op_code == :goto
          @dst.branch_flow
        elsif @dst.control_flow_type == :next
          @dst.next_flow
        elsif @dst.unconditional_branch_flow?
          @dst.unconditional_branch_flow
        else
          raise "can't point to next: #{to_label(nil)}"
        end
      end

      def next_flow?
        if @dst.op_code == :goto
          true
        elsif @dst.control_flow_type == :next
          true
        elsif @dst.unconditional_branch_flow?
          true
        else
          false
        end
      end

      def point_to_next_instruction
        reinstall do
          if @dst.op_code == :goto
            @dst = @dst.branch_flow.dst
            raise "dst is nil" if @dst.nil?
          elsif @dst.control_flow_type == :next
            @dst = @dst.next_flow.dst
            #p self.dst.to_label(self)
            raise "dst is nil" if @dst.nil?
          elsif @dst.unconditional_branch_flow?
            @dst = @dst.unconditional_branch_flow.dst
          else
            raise "can't point to next: #{to_label(nil)}"
          end
        end
      end

      def src_flow=(src_flow)
        raise
        #@src = src_flow.src
        #src_flow.src.next = self
      end
    end

    class NextControlFlow < ControlFlow
      def type
        :next
      end

      def dynamic_dst?
        false
      end

      def install
        super.tap do
          @src.next = self
          @dst.previous = self
        end
      end

      def uninstall
        super.tap do
          @src.next = nil
          @dst.previous = nil
        end
      end
    end

    class EntryInst < Inst
      def initialize(entry_flow)
        @entry_flow = entry_flow
        super(nil)
      end

      def to_label(optimizer)
        if optimizer.respond_to?(:compiled_code)
          optimizer.compiled_code.inspect
        else
          "<compiled code>"
        end
      end
    end

    class EntryControlFlow < ControlFlow
      def initialize(dst)
        super(EntryInst.new(self), dst)
      end

      def incoming_flows
        [self]
      end

      def dynamic_dst?
        true
      end

      def install
        super.tap do
          @dst.previous = self
        end
      end

      def uninstall
        super.tap do
          @dst.previous = nil
        end
      end
    end

    class BranchControlFlow < ControlFlow
      def initialize(src, dst, bytecode)
        raise "not branch instruction" if src.control_flow_type == :next
        super(src, dst)
        @bytecode = bytecode
      end

      def dynamic_dst?
        true
      end

      def type
        :branch
      end

      def install
        super.tap do
          @dst.branch_flows.push(self)
          @dst.incoming_flows.push(self)
        end
      end

      def uninstall
        super.tap do
          @dst.branch_flows.delete(self)
          @dst.incoming_flows.delete(self)
        end
      end

      def to_bytecode(instruction)
        instruction.branch_flow.dst.ip
      end
    end

    class ControlFlowAnalysis < Analysis
      def reset
        optimizer.control_flows.clear
      end

      def optimize
        reset
        previous = nil
        optimizer.add_control_flow(optimizer.entry_flow)
        optimizer.each_instruction do |instruction|
          if previous and
             previous.op_code != :goto and
             previous.op_code != :ret and
             previous.op_code != :reraise
            optimizer.add_control_flow(NextControlFlow.new(previous, instruction))
          end
          if instruction.control_flow_type == :branch or
             instruction.control_flow_type == :handler
            optimizer.add_control_flow(instruction.branch_flow)
          end
          previous = instruction
        end
      end
    end

    class ControlFlowPrinter < Analysis
      def optimize
        g = GraphViz.new(:G, :type => :digraph)
        g[:fontname] = "monospace"
        #g[:page] = "82,117"
        #g.fontsize = '5'

        optimizer.each_instruction do |instruction|
          node = g.add_nodes(instruction.to_label(optimizer))
          node.shape = 'rect'
          node.fontname = 'monospace'
          #node.fontsize = '18'
        end

        optimizer.control_flows.each do |control_flow|
          #p control_flow.class
          node1 = g.add_nodes(control_flow.src.to_label(optimizer))
          node1.shape = 'rect'
          node1.fontname = 'monospace'
          #node1.fontsize = '18'
          node2 = g.add_nodes(control_flow.dst.to_label(optimizer))
          node2.shape = 'rect'
          node2.fontname = 'monospace'
          #node2.fontsize = '18'
          edge = g.add_edges(node1, node2)
          edge.arrowhead = 'empty' if control_flow.static_dst?
          edge.arrowsize = '1.7'
          if not control_flow.spots.empty?
            edge.label = " #{control_flow.spots.collect {|s| s.to_label(optimizer) }.join("\n")}"
            edge.fontname = 'monospace'
            edge.fontsize = '11'
          end
          edge.style = 'dashed' if control_flow.removed?
        end

        g.output(:pdf => "control_flow.pdf")
        g.output(:ps => "control_flow.ps")
        g.output(:svg => "control_flow.svg")
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

      def take_snapshot
        other = dup
        other.instance_variable_set(:@selector, @selector.dup)
        other.instance_variable_set(:@place_holders, @place_holders.dup)
        other.instance_variable_set(:@results, @results.dup)
        other
      end

      def feed(previous, inst)
        p [self.object_id, self.class, @results.to_a.size, previous.to_s, inst.to_s]
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
          when :any
            1
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
        #p @results.map(&:last)
        spot = create_spot
        @results.each do |prev, cur, match|
          unless self.class.translator.include?(match)
            on_translate(spot, prev, cur)
            @scalar.optimizer.unlink(spot, prev, cur)
          end
        end

        false
      end

      def create_spot
        Spot.new(type)
      end

      def on_translate(spot, prev, cur)
      end
    end

    class PushLocalRemover < Matcher
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

    class PushIVarRemover < Matcher
      before [
        [:set_ivar, :ivar0],
        [:pop],
        :no_stack_changes,
        [:push_ivar, :ivar0],
      ]

      after [
        [:set_ivar, :ivar0],
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

      def type
        :nil_remove
      end
    end

    class Spot
      def initialize(type)
        @type = type
      end

      def to_label(optimizer)
        "#{@type}#{object_id}"
      end
    end

    class InfiniteLoop < Matcher
      before [
        [:push_true],
        [:goto_if_false],
      ]

      after [
      ]

      def type
        :infinite_loop
      end

      def on_translate(spot, prev, cur)
        if cur.op_code == :push_true and
           cur.next.dst.incoming_flows == [cur.next]
          cur.incoming_flows.each(&:remove)
          cur.incoming_flows.each {|f| f.add_spot(spot) }
        elsif prev.op_code == :push_true and
           cur.op_code == :goto_if_false and
           cur.incoming_flows == [prev.next]
          cur.unconditional_branch_flow = cur.next
          #cur.branch_flow.remove
        end
      end
    end

    class Prune < Optimization
      def prune_unused_insts
        optimizer.each_instruction do |inst|
          # p inst.to_label(optimizer)
          #   p inst.next.remove if inst.next
          #inst.incoming_flows(&:unremove)
          #inst.next.unremove if inst.next
          #optimizer.remove_control_flow(inst.next)
          #inst.prev_flow.unremove if inst.prev_flow
          #p inst.to_label(nil)
          #p inst.incoming_flows.map{|f| f.to_label(nil)}
          if inst.incoming_flows.empty? or inst.incoming_flows.all?(&:removed?)
            #inst.next.point_to_next_instruction i
            #inst.raw_remove
            next_flow = inst.static_next_flow

            next if next_flow.dst.op_code == :ret
            next_flow.point_to_next_instruction
            #next_inst = next_flow.dst
            #next_flow.uninstall
            #optimizer.remove_control_flow(next_flow)

            #if next_inst.incoming_flows.empty?
            #  next_inst.raw_remove
            #end

            #break unless inst.next
            #inst = inst.next.dst
          end
          #inst.prev_flow.unremove if inst.prev_flow
        end
      end

      def optimize
        moved_flows = []

        optimizer.each_instruction do |inst|
          if inst.incoming_flows.all?(&:removed?)
            inst.incoming_flows.dup.each do |flow|
              next_flow = flow.next_flow
              flow.point_to_next_instruction
              initial_spots = flow.spots.dup
              flow.add_spots(next_flow.spots)
              if next_flow.src.incoming_flows.all?(&:removed?)
                next_flow.src.remove
                optimizer.remove_control_flow(next_flow)
              end

              if next_flow.removed?
                next_flow = flow.next_flow
                flow.point_to_next_instruction
                flow.add_spots(next_flow.spots)
                if next_flow.src.incoming_flows.all?(&:removed?)
                  next_flow.src.remove
                  optimizer.remove_control_flow(next_flow)
                end
              end
              if (next_flow.spots - initial_spots).empty?
                flow.unremove
              end
            end
            inst.raw_remove
          elsif inst.incoming_flows.any?(&:removed?)
            p "partial #{inst.to_label(optimizer)}"

            flows = inst.incoming_flows
            next_flow = flows.detect(&:static_dst?)
            if next_flow.nil? or not next_flow.removed?
              flows.dup.select(&:dynamic_dst?).each do |branch_flow|
                next if not branch_flow.removed?
                branch_flow.point_to_next_instruction
              end
            elsif false
              inst = next_flow.dst
              flows.dup.select(&:dynamic_dst?).each do |branch_flow|
                if branch_flow.removed?
                  branch_flow.point_to_next_instruction
                  branch_flow.unremove
                else
                  new_inst = inst.dup
                  after_inst = branch_flow.src
                  after_inst.previous.src.insert_after(new_inst)
                  after_inst.previous.dst = new_inst

                  branch_flow.point_to_next_instruction
                  optimizer.add_control_flow(NextControlFlow.new(new_inst, after_inst))
                end
              end
              inst.remove
              optimizer.remove_control_flow(inst.next)
            end
          end
        end
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
            when Entry
              #p event
              reset
            when Restore
              pop
              #p event
            when Save, Terminate
              #ap @states.collect(&:take_snapshot)
              push
              #p event
            else
              #p event.compact.map{|i| i.to_label(optimizer)}
              transformed ||= feed(event)
            end
          end
        end
      end

      def reset
        @states = [
          #PushLocalRemover.new(optimizer, self),
          #PushIVarRemover.new(optimizer, self),
          NilRemover.new(optimizer, self),
          InfiniteLoop.new(optimizer, self),
        ]

        @snap_shots = []
      end

      def push
        @snap_shots.push(@states)
      end

      def pop
        @states = @snap_shots.last.collect(&:take_snapshot)
      end

      def feed(event)
        raise "no state" if @states.nil?
        @states.each do |state|
          state.feed(*event)
        end

        false
      end

      def scalar_each
        entry = optimizer.first_instruction
        stack = [[optimizer.first_flow.src, entry]]
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
                  stack.push([current, current.next_flow.dst])
                  stack.push([current, current.branch_flow.dst])
                  yield [previous, current]
                  current = nil
                else
                  previous = current
                  current = current.branch_flow.dst
                end
              else
                current = nil
              end
            elsif current.control_flow_type == :return
              break
            else
              yield [previous, current]
              previous = current
              current = current.next_flow.dst
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
  while true
    hello
  end
end
#code = Array.instance_method(:set_index).executable
code = method(:loo).executable
#code = "".method(:dump).executable
#code = "".method(:[]).executable
#code = "".method(:start_with?).executable
#code = [].method(:cycle).executable
opt = Rubinius::Optimizer.new(code)
opt.add_pass(Rubinius::Optimizer::ControlFlowAnalysis)
opt.add_pass(Rubinius::Optimizer::ScalarTransform)
opt.add_pass(Rubinius::Optimizer::Prune)
#opt.add_pass(Rubinius::Optimizer::ControlFlowAnalysis)
#opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)

opt.add_pass(Rubinius::Optimizer::ControlFlowPrinter)
#opt.add_pass(Rubinius::Optimizer::DataFlowPrinter)

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

#puts code
#puts optimized_code.decode.size

def measure
  started_at = Time.now
  yield
  puts Time.now - started_at
end
# invoke(@name, @defined_in, obj, args, block)
hello = [:world, :invoke, :name, :obj, :args, :block, :sat, :odct]
result = nil
arg = [3...5, ["world", "haa"]]

5.times do
5.times do
      p optimized_code.decode.size
  measure do
    100000.times do
      result = optimized_code.invoke(:loo, Array, hello.dup, arg, nil)
    end
  end
end
#p result
puts

5.times do
      p code.decode.size
  measure do
    100000.times do
      result = code.invoke(:loo, Array, hello.dup, arg, nil)
    end
  end
end
#p result
puts
end

#opt = Rubinius::Optimizer.new(optimized_code)
#opt.add_pass(Rubinius::Optimizer::ControlFlowAnalysis)
#opt.add_pass(Rubinius::Optimizer::ControlFlowPrinter)
#opt.run

p result

return
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
