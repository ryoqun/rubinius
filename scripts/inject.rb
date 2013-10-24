require 'awesome_print'
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
      attr_reader :instruction, :imports, :exports, :incoming_branch_flows, :incoming_flows, :entry_flow
      attr_accessor :op_rands, :ip,
                    :following_instruction, :preceeding_instruction, :unconditional_branch_flow
      def initialize(instruction)
        @instruction = instruction
        @op_rands = nil

        @previous = @next = nil
        @incoming_branch_flows = []
        @incoming_flows = []

        @imports = []
        @exports = []

        @following_instruction = @preceeding_instruction = nil
        @entry_flow = nil

        @ip = 0
        @generation = 0
        @unconditional_branch_flow = nil
      end

      def unconditional_branch_flow?
        !!@unconditional_branch_flow
      end

      def previous_inst
        @previous.src_inst
      end

      def next_inst
        @next.dst_inst
      end

      def previous_flow
        @previous
      end

      def previous_flow=(prev)
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
        elsif flow_type == :next
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
        @previous = @entry_flow = EntryFlow.new(self)
        self
      end

      def dup
        super.tap do |new|
          new.instance_variable_set(:@generation, rand(100000))
          new.incoming_flows.clear
          new.incoming_branch_flows.clear
        end
      end

      def entry_inst?
        !!@entry_flow
      end

      def next_flow
        @next
      end

      def next_flow=(next_flow)
        @next = next_flow
      end

      def prev_flow
        @previous
      end

      def incoming_branch_flows
        @incoming_branch_flows
      end

      def mark_raw_remove
        @remove_mark = true
      end

      def mark_for_removal?
        @remove_mark
      end

      def raw_remove
        if following_instruction
          following_instruction.preceeding_instruction = preceeding_instruction
        end
        if preceeding_instruction
          preceeding_instruction.following_instruction = following_instruction
        end

        self
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

      def flow_type
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
        raise "not branch flow #{op_code} #{self.inspect}" unless branch_flow?
        @op_rands.first
      end

      def branch_flow?
        flow_type == :branch or flow_type == :handler
      end

      def branch_flow=(branch)
        raise "no #{op_code} #{self.inspect}" unless branch_flow?
        @op_rands[0] = branch
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

    attr_reader :compiled_code, :flows, :data_flows
    attr_accessor :entry_flow
    def initialize(compiled_code)
      @compiled_code = compiled_code
      @passes = []
      @flows = []
      @data_flows = []
      decode
    end

    def remove_flow(flow)
      raise "baaad" if flow.nil?
      @flows.delete(flow)
    end

    def first_flow
      @entry_flow
    end

    def first_instruction
      @entry_flow.dst_inst
    end

    def add_data_flow(data_flow)
      data_flow.install
      @data_flows.push(data_flow)
    end

    def add_flow(flow)
      flow.install
      @flows.push(flow)
      flow
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
          @entry_flow = inst.previous_flow
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
            BranchFlow.new(inst, ip_to_inst[bytecode], bytecode)
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
        following_instruction = instruction.following_instruction
        yield instruction
        instruction = following_instruction
      end
    end

    def generate_bytecode
      sequence = []
      used = {}

      stacks = [first_instruction]
      until stacks.empty?
        instruction = stacks.shift

        if instruction
          if instruction.previous_flow && instruction != first_instruction
            rewinds = []
            previous = instruction.previous_inst
            while not used.include?(previous) and not previous.incoming_flows.empty? # remove empty future
              rewinds << previous
              break if previous.previous_flow.nil?
              previous = previous.previous_inst
            end
            rewinds.reverse.each do |rewind|
              sequence << rewind
              used[rewind] = true
            end
          end
          if not used.include?(instruction)
            sequence << instruction
            used[instruction] = true
          end
        end

        while instruction
          if next_flow = instruction.next_flow
            instruction = next_flow.dst_inst
            if instruction.branch_flow? and (branch_flow = instruction.branch_flow)
              branch_instruction = stacks.delete(branch_flow.dst_inst) ||
                                     branch_flow.dst_inst
              stacks.push(branch_instruction)
            end
          elsif instruction.op_code == :goto
            goto_branch = stacks.last
            stacks.push(stacks.delete(goto_branch))
            break
          else
            instruction = nil
          end

          if instruction
            break if used.include?(instruction)
            sequence << instruction
            used[instruction] = true
          end
        end
      end

      ip = 0
      sequence.each do |inst|
        inst.ip = ip
        ip += inst.instruction_width
      end

      bytecodes = []
      sequence.each do |inst|
        bytecodes << inst.bytecode
        inst.op_rands.each do |op_rand|
          bytecodes << op_rand.to_bytecode(inst)
        end
      end

      bytecodes
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

      bytecodes = generate_bytecode
      raise "too small, is there call flow analysis???" if bytecodes.size == 1

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
          instruction.incoming_branch_flows.each do |goto|
            if goto.src_inst.op_code == :goto or
               goto.src_inst.op_code == :goto_if_true or
               goto.src_inst.op_code == :goto_if_false
              branch_target_found = true
              stacks << goto_to_stack[goto.src_inst] if goto_to_stack.has_key?(goto.src_inst)
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
        suffix = nil #"(branch_flow)" if data.respond_to?(:incoming_branch_flows) and not data.incoming_branch_flows.empty?
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

    class Flow
      attr_reader :src_inst, :dst_inst, :spots, :previous_spots
      def initialize(src_inst, dst_inst)
        @src_inst = src_inst
        raise "src_inst is nil" if @src_inst.nil?
        @dst_inst = dst_inst
        raise "dst_inst is nil" if @dst_inst.nil?
        @remove = false
        @installed = false
        @spots = []
        @previous_spots = []
        @metadata = {}
      end

      def metadata(spot)
        @metadata[spot] ||= {}
      end

      def all_metadata
        @metadata
      end

      def add_spot(spot)
        @spots.push(spot) unless @spots.include?(spot)
      end

      def add_previous_spot(spot)
        @previous_spots.push(spot) unless @spots.include?(spot) and @previous_spots.include?(spot)
      end

      def add_spots(spots)
        @spots.concat(spots).uniq!
      end

      def first_flow?
        @spots.all? do |spot|
          spot.first_flow?(self)
        end
      end

      def to_label(optimizer)
        "#{@src_inst.to_label(optimizer).strip}=#{mark_removed? ? "x" : "="}>#{@dst_inst.to_label(optimizer).strip}"
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

      def mark_remove
        @remove = true
        self
      end

      def unmark_remove
        @remove = false
        self
      end

      def mark_removed?
        @remove
      end

      def next_flow
        if @dst_inst.op_code == :goto
          @dst_inst.branch_flow
        elsif @dst_inst.flow_type == :next
          @dst_inst.next_flow
        elsif @dst_inst.unconditional_branch_flow?
          @dst_inst.unconditional_branch_flow
        else
          raise "can't point to next: #{to_label(nil)}"
        end
      end

      def next_flow?
        if @dst_inst.op_code == :goto
          true
        elsif @dst_inst.flow_type == :next
          true
        elsif @dst_inst.unconditional_branch_flow?
          true
        else
          false
        end
      end

      def point_to_next_instruction
        reinstall do
          if @dst_inst.op_code == :goto
            @dst_inst = @dst_inst.branch_flow.dst_inst
            raise "dst_inst is nil" if @dst_inst.nil?
          elsif @dst_inst.flow_type == :next
            @dst_inst = @dst_inst.next_inst
            #p self.dst_inst.to_label(self)
            raise "dst_inst is nil" if @dst_inst.nil?
          elsif @dst_inst.unconditional_branch_flow?
            @dst_inst = @dst_inst.unconditional_branch_flow.dst_inst
          else
            raise "can't point to next: #{to_label(nil)}"
          end
        end
      end

      def change_src_dst(src_inst, dst_inst)
        raise "src_inst or dst_inst is nil" if src_inst.nil? or dst_inst.nil?
        reinstall do
          @src_inst = src_inst
          @dst_inst = dst_inst
        end
      end
    end

    class NextFlow < Flow
      def type
        :next
      end

      def dynamic_dst?
        false
      end

      def install
        super.tap do
          @src_inst.next_flow = self
          @dst_inst.previous_flow = self
        end
      end

      def uninstall
        super.tap do
          @src_inst.next_flow = nil
          @dst_inst.previous_flow = nil
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

    class EntryFlow < Flow
      def initialize(dst_inst)
        super(EntryInst.new(self), dst_inst)
        @incoming_flows = [self]
      end

      def dynamic_dst?
        true
      end

      def install
        super.tap do
          @dst_inst.previous_flow = self
        end
      end

      def uninstall
        super.tap do
          @dst_inst.previous_flow = nil
        end
      end
    end

    class BranchFlow < Flow
      def initialize(src_inst, dst_inst, bytecode)
        raise "not branch instruction" if src_inst.flow_type == :next
        super(src_inst, dst_inst)
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
          #@src_inst.branch_flow = self
          @dst_inst.incoming_branch_flows.push(self)
          @dst_inst.incoming_flows.push(self)
        end
      end

      def uninstall
        super.tap do
          #@src_inst.branch_flow = nil
          @dst_inst.incoming_branch_flows.delete(self)
          @dst_inst.incoming_flows.delete(self)
        end
      end

      def to_bytecode(instruction)
        instruction.branch_flow.dst_inst.ip
      end
    end

    class FlowAnalysis < Analysis
      def reset
        optimizer.flows.clear
      end

      def optimize
        reset
        previous = nil
        optimizer.add_flow(optimizer.entry_flow)
        optimizer.each_instruction do |instruction|
          if previous and
             previous.op_code != :goto and
             previous.op_code != :ret and
             previous.op_code != :reraise
            optimizer.add_flow(NextFlow.new(previous, instruction))
          end
          if instruction.flow_type == :branch or
             instruction.flow_type == :handler
            optimizer.add_flow(instruction.branch_flow)
          end
          previous = instruction
        end
      end
    end

    class FlowPrinter < Analysis
      def initialize(*args, file, &block)
        super(*args, &block)
        @file = file
      end

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

        optimizer.flows.each do |flow|
          #p flow.class
          node1 = g.add_nodes(flow.src_inst.to_label(optimizer))
          node1.shape = 'rect'
          node1.fontname = 'monospace'
          node1.style = 'dashed' if flow.src_inst.mark_for_removal?
          #node1.fontsize = '18'
          node2 = g.add_nodes(flow.dst_inst.to_label(optimizer))
          node2.shape = 'rect'
          node2.fontname = 'monospace'
          node2.style = 'dashed' if flow.dst_inst.mark_for_removal?
          #node2.fontsize = '18'
          edge = g.add_edges(node1, node2)
          edge.arrowhead = 'empty' if flow.static_dst?
          edge.arrowsize = '1.7'
          labels = []
          if not flow.spots.empty?
            labels += flow.spots.collect {|s| "#{s.to_label(optimizer)} #{s.position(flow)}" }
          end
          if not flow.previous_spots.empty?
            labels += flow.previous_spots.collect {|s| "#{s.to_label(optimizer)} PREV" }
          end
          if not flow.all_metadata.empty?
            labels += [flow.all_metadata.collect {|k, v| [k.to_label(optimizer), v]}.inspect]
          end
          labels += [flow.src_inst.to_s]
          labels += [[flow.src_inst.incoming_flows.collect(&:src_inst)].to_s.split(", ").join("\n")]
          if not labels.empty?
            edge.label = labels.join("\n")
            edge.fontname = 'monospace'
            edge.fontsize = '11'
          end
          edge.style = 'dashed' if flow.mark_removed?
        end

        g.output(:pdf => "#{base_name}.pdf")
        #g.output(:ps => "flow.ps")
        g.output(:svg => "#{base_name}.svg")
      end

      def base_name
        if @file
          "flow_#{@file}"
        else
          "flow"
        end
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

      def feed(previous_flow, flow)
        #p [self.object_id, self.class, @results.to_a.size, previous.to_s, inst.to_s]
        if @cursor.nil?
          @cursor = 0
          @selector = self.class.selector.dup
          @place_holders = {}
          @results = []
        end
        matcher = @selector[@cursor]
        advance = match(flow.dst_inst, matcher)
        if advance.nil? and matcher.is_a?(Symbol)
          @cursor += 1
          matcher = @selector[@cursor]
          advance = match(flow.dst_inst, matcher)
        end

        if advance.nil?
          @cursor = nil
        else
          @cursor += advance
          @results << [previous_flow, flow, matcher]

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
            if inst.op_code == :goto or inst.op_code == :check_interrupts
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
        spot = create_spot(@results)
        @scalar.add_spot(spot)
        #next if @results.first[1].spots.any?{|s| p s.type ;s.type == type }

        @results.each do |previous_flow, flow, match|
          unless self.class.translator.include?(match)
            return if flow.spots.size > 0

            #previous_flow.add_previous_spot(spot)
            #spot.add_previous_flow(previous_flow)

            flow.add_spot(spot)
            spot.add_flow(flow)
          end
        end


        false
      end

      def create_spot(results)
        Spot.new(self, results)
      end

      def on_translate(spot, flow)
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

      def type
        :push_local
      end
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

      def type
        :push_ivar
      end
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
      attr_reader :type
      def initialize(matcher, results)
        @matcher = matcher
        @type = matcher.type
        @results = results
        @flows = []
        @previous_flows = []
      end

      def to_label(optimizer)
        "#{@type}_#{object_id.to_s(0x10)}"
      end

      def first_flow?(flow)
        @flows.first == flow
      end

      def position(flow)
        if @flows.index(flow)
          "#{(@flows.index(flow) + 1)}/#{(@flows.size)}"
        else
          "REMOVED"
        end
      end

      def add_flow(flow)
        @flows.push(flow) unless @flows.include?(flow)
      end

      def add_previous_flow(flow)
        @previous_flows.push(flow) unless @flows.include?(flow) and @previous_flows.include?(flow)
      end

      def transform
        if isolated?
          @results.each do |previous_flow, flow, match|
            unless @matcher.class.translator.include?(match)
              #on_translate(spot, flow)
              flow.mark_remove
            end
          end
        else
          flows = []
          @results.each do |previous_flow, flow, match|
            unless @matcher.class.translator.include?(match)
              flows << flow
              flow.metadata(self)[:isolated] = false
            end
          end

          if forwardable?(self)
            raise "bad" if flows.size != 2
            index = 0
            flow = flows.first
            return if flow.is_a?(NextFlow)
            next_flow = flow.next_flow
            #puts
            #ap flow.to_label(nil)
            #ap flows.last.to_label(nil)
            until next_flow == flows.last
              flow.point_to_next_instruction
              next_flow = flow.next_flow
            end
            flow.point_to_next_instruction
            flow.point_to_next_instruction
          else
            flows.each do |flow|
              flow.metadata(self)[:cover] = false
            end
          end
        end
      end

      def forwardable?(spot)
        forwardable = false
        @results.each do |previous_flow, flow, match|
          unless @matcher.class.translator.include?(match)
            next_flow = flow
            while next_flow = next_flow.dst_inst.static_next_flow
              if next_flow.spots == [spot]
                forwardable = true
              elsif not next_flow.spots.empty?
                return false
              end
            end
          end
        end

        forwardable
      end

      def isolated?
        @results.each do |previous_flow, flow, match|
          unless @matcher.class.translator.include?(match)
            if flow.dst_inst.incoming_flows.size > 1
              comparison = flow.dst_inst.incoming_flows.collect do |flow|
                [
                flow.spots.map(&:type),
                flow.spots.map{|s| s.position(flow) },
                ]
              end
              if comparison.uniq.size > 1
                return false
              end
            end
          end
        end

        true
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
           cur.next.dst_inst.incoming_flows == [cur.next]
          cur.incoming_flows.each(&:mark_remove)
          cur.incoming_flows.each {|f| f.add_spot(spot) }
        elsif prev.op_code == :push_true and
           cur.op_code == :goto_if_false and
           cur.incoming_flows == [prev.next]
          cur.unconditional_branch_flow = cur.next
          #cur.branch_flow.mark_remove
        end
      end
    end

    class RemoveCheckInterrupts < Optimization
      INTERRUPTABLE_INSTRUCTIONS = [
        :yield_stack,
        :send_stack,
      ]

      def optimize
        optimizer.each_instruction do |inst|
          if inst.op_code == :check_interrupts
            removable = false
            check_interrupts = inst
            while inst.previous_flow and inst.incoming_flows.size == 1
              p inst.op_code
              if INTERRUPTABLE_INSTRUCTIONS.include?(inst.op_code)
                removable = true
                break
              end
              inst = inst.previous_inst
            end
            if removable
              p :ok_removala
              check_interrupts.previous_inst.next_flow.point_to_next_instruction
            end
          end
        end
      end
    end

    class GotoRet < Optimization
      def optimize
        optimizer.each_instruction do |inst|
          if inst.op_code == :goto and
             inst.branch_flow.dst_inst.op_code == :ret and
             inst.incoming_flows.size == 1 and
             not inst.previous_flow.nil?
            goto = inst

            new_goto = goto.branch_flow.dst_inst.dup

            previous_inst = goto.previous_flow.src_inst
            goto.previous_flow.change_src_dst(previous_inst, new_goto)

            optimizer.remove_flow(goto.branch_flow)

            goto.raw_remove
            goto.insert_after(previous_inst)
          end
        end
      end
    end

    class GoToRemover < Optimization
      def optimize
        optimizer.each_instruction do |inst|
          if inst.op_code == :goto
            inst.incoming_flows.dup.each do |incoming_flow|
              if incoming_flow.src_inst.op_code == :goto_if_true
                puts "goto / goto if true"
                puts incoming_flow.src_inst.incoming_flows.size
                #incoming_flow.point_to_next_instruction
              elsif incoming_flow.src_inst.op_code == :goto_if_false
                #incoming_flow.point_to_next_instruction
                #p inst.previous
                if incoming_flow.src_inst.next_flow == inst.previous_flow and
                   inst.incoming_flows.size == 1
                  #puts "goto / goto if false next"
                  goto_if_false = incoming_flow.src_inst
                  goto = inst
                  goto_if_false.next_flow.point_to_next_instruction
                  #goto.branch_flow.uninstall
                  #goto.branch_flow.mark_remove
                  #optimizer.remove_flow(.mark_remove)

                  goto.raw_remove
                  #optimizer.remove_flow(inst.previous)
                  #p incoming_flow.src_inst.branch_flow
                  #p incoming_flow.dst_inst
                  #incoming_flow.reinstall do
                    #incoming_flow.instance_variable_set(:@dst_inst, inst.next_flow)
                  #end
                  ##incoming_flow.src_inst.next_flow.point_to_next_instruction
                  #puts inst.incoming_flows.size
                  #optimizer.remove_flow(inst.branch_flow.mark_remove)
                  #p incoming_flow.src_inst.branch_flow
                  #inst.raw_remove
                  #break
                else
                  puts "goto / goto if false branch"
                  puts incoming_flow.src_inst.incoming_flows.size
                  #incoming_flow.src_inst.branch_flow.reinstall do
                  #  incoming_flow.src_inst.branch_flow.instance_variable_set(:@dst_inst, inst.branch_flow.dst_inst)
                  #end
                  #optimizer.remove_flow(inst.branch_flow)
                end
              elsif incoming_flow.src_inst.op_code == :goto
                puts "goto / goto"
                puts inst
                puts incoming_flow.src_inst.incoming_flows.size
                #next = incoming_flow.next_flow.raw_remove
                #incoming_flow.point_to_next_instruction
                #inst.raw_remove
              end
            end
            #inst.raw_remove if inst.incoming_flows.empty?
          end
        end
      end
    end

    class Prune < Optimization
      def optimize
        moved_flows = []

        optimizer.each_instruction do |inst|
          if inst.incoming_flows.all?(&:mark_removed?)
            used_spots = []

            inst.incoming_flows.dup.each do |flow|
              #next unless flow.first_flow?
              used_spots = flow.spots.dup

                next_flow = flow.next_flow
                flow.point_to_next_instruction
                #flow.add_spots(next_flow.spots)
                if next_flow.src_inst.incoming_flows.all?(&:mark_removed?)
                  optimizer.remove_flow(next_flow)
                end
              if next_flow.mark_removed?
                next_flow = flow.next_flow
                flow.point_to_next_instruction
                #flow.add_spots(next_flow.spots)
                if next_flow.src_inst.incoming_flows.all?(&:mark_removed?)
                  optimizer.remove_flow(next_flow)
                end
              end

              #if (next_flow.spots - initial_spots).empty?
                flow.unmark_remove
              #end
            end
          elsif inst.incoming_flows.any?(&:mark_removed?)
            #p "partial #{inst.to_label(optimizer)}"

            flows = inst.incoming_flows
            next_flow = flows.detect(&:static_dst?)
            if next_flow.nil? or not next_flow.mark_removed?
              flows.dup.select(&:dynamic_dst?).each do |branch_flow|
                next if not branch_flow.mark_removed?
                branch_flow.point_to_next_instruction
                branch_flow.unmark_remove
              end
            else
              inst = next_flow.dst_inst
              flows.dup.select(&:dynamic_dst?).each do |branch_flow|
                if branch_flow.mark_removed?
                  branch_flow.point_to_next_instruction
                  branch_flow.unmark_remove
                else
                  new_inst = inst.dup
                  optimizer.remove_flow(inst.static_next_flow)
                  inst.raw_remove
                  after_inst = branch_flow.src_inst
                  after_inst.previous.change_src_dst(after_inst.previous.src_inst, new_inst)

                  branch_flow.point_to_next_instruction
                  branch_flow.unmark_remove
                  optimizer.add_flow(NextFlow.new(new_inst, after_inst))
                end
              end
              #optimizer.remove_flow(next_flow)
            end
          end
        end
      end
    end

    class ScalarTransform < Optimization
      def add_spot(spot)
        @spots << spot
      end

      def optimize
        @spots = []
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
              #pop
              #p event
              reset
            when Save, Terminate
              #ap @states.collect(&:take_snapshot)
              #push
              #p event
            else
              #p event.compact.map{|i| i.to_label(optimizer)}
              transformed ||= feed(event)
            end
          end
        end
        @spots.each(&:transform)
      end

      def reset
        @states = [
          PushLocalRemover.new(optimizer, self),
          PushIVarRemover.new(optimizer, self),
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

      def scalar_each(&block)
        entry = optimizer.first_instruction.next_flow
        loop_marks = {}
        previous = nil
        stack = [[previous, optimizer.first_flow]]

        yield Entry.new
        until stack.empty?
          previous, current = stack.pop
          while current
            if current.dst_inst.flow_type == :branch
              if loop_marks[current].nil?
                loop_marks[current] = true
                if current.dst_inst.next_flow
                  yield Save.new
                  stack.push([current, current.dst_inst.next_flow])
                  stack.push([current, current.dst_inst.branch_flow])
                  yield_flow(previous, current, &block)
                  previous = current
                  current = nil
                else
                  previous = current
                  current = current.next_flow
                end
              else
                previous = current
                current = nil
              end
            elsif current.dst_inst.flow_type == :return
              break
            else
              #if current.dst_inst.incoming_flows.size == 1
                yield_flow(previous, current, &block)
              #else
              #  yield Entry.new
              #end
              previous = current
              current = current.dst_inst.next_flow
            end
          end
          yield Restore.new
        end
        yield Terminate.new
      end

      def yield_flow(previous, current)
        yield([previous, current])
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

    class PruneUnused < Optimization
      def optimize
        begin
          found = false
          optimizer.each_instruction do |instruction|
            if instruction.incoming_flows.empty? # maybe we should also check next but haven't a convenient api yet.
              instruction.raw_remove
            end
          end
          optimizer.flows.dup.each do |flow|
            next if flow == optimizer.first_flow
            if flow.src_inst.incoming_flows.empty?
              found = true
              flow.mark_remove
              flow.uninstall
              optimizer.remove_flow(flow)
              flow.src_inst.raw_remove
            end
          end
        end while found
      end
    end
  end
end

#code = Rubinius::Optimizer::Inst.instance_method(:stack_consumed).executable
#code = File.method(:absolute_path).executable
def loo(_aa, _bb)
  i = 0
  while i < 10000
    @foo = true
    @bar = @foo
    @baz = @bar
    i += 1
  end
end
#code = Array.instance_method(:set_index).executable
code = method(:loo).executable
#code = "".method(:dump).executable
#code = "".method(:[]).executable
#code = "".method(:start_with?).executable
#code = "".method(:start_with?).executable
#code = Time.method(:at).executable
#code = [].method(:|).executable
#code = ARGF.method(:each_line).executable
#code = IO.instance_method(:each).executable
#code = IO.method(:binwrite).executable
#code = Regexp.method(:escape).executable
#code = Rational.instance_method(:/).executable
opt = Rubinius::Optimizer.new(code)
opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
opt.add_pass(Rubinius::Optimizer::FlowPrinter, "original")
opt.add_pass(Rubinius::Optimizer::ScalarTransform)
opt.add_pass(Rubinius::Optimizer::Prune)
opt.add_pass(Rubinius::Optimizer::PruneUnused)
opt.add_pass(Rubinius::Optimizer::GotoRet)
opt.add_pass(Rubinius::Optimizer::GoToRemover)
opt.add_pass(Rubinius::Optimizer::RemoveCheckInterrupts)
#opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
opt.add_pass(Rubinius::Optimizer::DataFlowPrinter)

optimized_code = opt.run
puts optimized_code.decode.size

opt = Rubinius::Optimizer.new(code)
opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
un_code = opt.run

#if ENV["opt"] == "true"
#  code = optimied_code
#else
#  code = un_code
#end

opt = Rubinius::Optimizer.new(optimized_code)
opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
opt.add_pass(Rubinius::Optimizer::FlowPrinter, "generated")
optimized_code = opt.run
puts optimized_code.decode.size
#opt = Rubinius::Optimizer.new(code)
#opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
##opt.add_pass(Rubinius::Optimizer::ScalarTransform)
#opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
#
#opt.add_pass(Rubinius::Optimizer::FlowPrinter)
#opt.add_pass(Rubinius::Optimizer::DataFlowPrinter)
#
#un_code = opt.run

#puts code

def measure
  started_at = Time.now
  yield
  Time.now - started_at
end
# invoke(@name, @defined_in, obj, args, block)
hello = [:world, :invoke, :name, :obj, :args, :block, :sat, :odct]
result = nil
arg = [3...5, ["world", "haa"]]

#p result
puts

1.times do
  puts optimized_code.decode.size
  puts un_code.decode.size
  unoptimized_time = 0
  5.times do
    unoptimized_time += measure do
      1000.times do
        un_code.invoke(:loo, Array, hello.dup, arg, nil)
      end
    end
  end

  optimized_time = 0
  5.times do
    optimized_time += measure do
      1000.times do
        optimized_code.invoke(:loo, Array, hello.dup, arg, nil)
      end
    end
  end

  p unoptimized_time/optimized_time
end
#p result
puts


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
