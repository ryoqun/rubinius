#require 'awesome_print'
#require 'graphviz'

# generateg by
#   cat runtime/gems/rubinius-compiler-2.0.4/lib/rubinius/compiler/generator_methods.rb | grep -v -E '(@ip|@stream|  @instruction|close|right|left|used_at|new_basic_block|find_literal|generators|current_block = )' | tee generator_methods.rb | ruby -c -

if RUBY_DESCRIPTION !~ /rubinius/i or
   __FILE__ == $0
  require './scripts/generator_methods'
end

module Rubinius
  class Optimizer
    class OpRand
      attr_accessor :bytecode
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

      def +(other)
        to_i + other
      end

      def *(other)
        to_i * other
      end

      def times(*args, &block)
        to_i.times(*args, &block)
      end
    end

    module Endpoint
    end

    class Literal < OpRand
      include Endpoint
      def to_label(optimizer)
        "<literal: #{(optimizer.literals[bytecode] || bytecode).inspect.to_s[0, 20]}>"
      end

      def to_inst
        "literal (to_inst)"
      end

      def <(other)
        bytecode < other
      end

      def >(other)
        bytecode > other
      end
    end

    class Serial < OpRand
      def to_i
        bytecode
      end
    end

    class Local < OpRand
      def to_label(optimizer)
        "<local: #{optimizer.local_names[bytecode] || bytecode}>"
      end

      def to_inst
        "some thing"
      end
    end

    class Parameter < OpRand
      def to_label(optimizer)
        "<param: #{optimizer.local_names[bytecode] || bytecode}>"
      end
    end

    class StackLocal < OpRand
      def to_label(optimizer)
        "<stk_local: #{optimizer.local_names[bytecode] || bytecode}>"
      end
    end

    class Type < OpRand
      def to_label(optimizer)
        "type"
      end
    end

    class MethodGuard
    end

    class Inst
      attr_reader :instruction, :imports, :exports, :incoming_branch_flows, :incoming_flows, :guards
      attr_accessor :op_rands, :ip, :line,
                    :following_instruction, :preceeding_instruction, :unconditional_branch_flow,
                    :call_site
      def to_inst
        self
      end

      def initialize(instruction)
        @instruction = instruction
        @op_rands = nil

        @previous = @next = nil
        @incoming_branch_flows = []
        @incoming_flows = []

        @imports = []
        @exports = []

        @following_instruction = @preceeding_instruction = nil

        @ip = 0
        @generation = 0
        @unconditional_branch_flow = nil
        @line = 0
        @remove_mark = nil
        @guards = []
        @instruction_width = @bytecode = @flow_type = nil
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
        elsif flow_type == :raise or flow_type == :return
          nil
        elsif flow_type == :next
          next_flow
        elsif unconditional_branch_flow?
          unconditional_branch_flow
        else
          nil
        end
      end

      def signature
        raise "not send instruction" if op_code != :send_stack
        [
         op_rands[1].to_i,
         0,
         op_rands[1].to_i,
         nil,
         nil,
        ]
      end

      def to_s
        instruction.to_s
      end

      def inspect
        instruction.to_s
      end

      def dup
        super.tap do |new|
          new.instance_variable_set(:@generation, rand(100000))
          new.incoming_flows.clear
          new.incoming_branch_flows.clear
        end
      end

      def entry_inst?
        @previous.src_inst.is_a?(EntryInst)
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

      attr_writer :op_code
      def op_code
        if @op_code || @instruction
          @op_code || @instruction.instruction.opcode
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


      attr_writer :instruction_width
      def instruction_width
        @instruction_width || @instruction.instruction.width
      end

      attr_writer :bytecode
      def bytecode
        @bytecode || @instruction.instruction.bytecode
      end

      attr_writer :flow_type
      def flow_type
        return @flow_type if @flow_type
        @instruction.instruction.control_flow
      end

      attr_writer :label
      def to_label(optimizer)
        return @label if @label

        if @generation.zero?
          "#{"#{@line}: " if @line}#{instruction.to_s}"
        else
          "#{"#{@line}: " if @line}#{instruction.to_s} (#{@generation})"
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
        _read, write = W.send(op_code, *op_rands)
        write
      end

      def stack_consumed
        read, _write = W.send(op_code, *op_rands)
        read
      end
    end

    attr_reader :compiled_code, :flows, :data_flows, :basic_blocks, :exit_flows
    attr_reader :local_names, :literals, :local_count
    attr_reader :local_op_codes, :literal_op_codes
    attr_reader :source_data_flows, :sink_data_flows
    attr_accessor :entry_inst, :max_stack_size
    def initialize(compiled_code)
      @compiled_code = compiled_code
      @passes = []
      @flows = []
      @data_flows = []
      @source_data_flows = Hash.new{|hash, key| hash[key] = [] }
      @sink_data_flows = Hash.new{|hash, key| hash[key] = [] }
      @basic_blocks = []
      @definition_line = nil
      @exit_flows = []
      @local_names = compiled_code.local_names.to_a
      @literals = compiled_code.literals.to_a
      @local_count = compiled_code.local_count
      decode
    end

    def merge(optimizer)
      @flows.concat(optimizer.flows.reject{|flow| flow.src_inst.is_a?(EntryInst)})

      offset = @local_names.size
      optimizer.local_names.to_a.each.with_index do |local_name, index|
        if @local_names.include?(local_name)
          local_name = :"#{local_name}#{rand(1024)}"
        end
        @local_names << local_name
      end

      optimizer.local_op_codes.values.each do |local|
        local.bytecode += offset
      end

      offset = @literals.size
      optimizer.literals.to_a.each.with_index do |literal, index|
        @literals << literal
      end

      optimizer.literal_op_codes.values.each do |local|
        local.bytecode += offset
      end
    end

    def signature
      [
        @compiled_code.required_args,
        @compiled_code.post_args,
        @compiled_code.total_args,
        @compiled_code.splat,
        @compiled_code.block_index,
      ]
    end

    def remove_flow(flow)
      raise "baaad" if flow.nil?
      @flows.delete(flow)
    end

    def first_flow
      @entry_inst.next_flow
    end
    alias_method :entry_flow, :first_flow

    def first_instruction
      first_flow.dst_inst
    end

    def receiver_data(send_inst)
      data_flows = find_source_data_flows(send_inst)
    end

    def find_sink_data_flows(end_point)
      @sink_data_flows[end_point]
    end

    def find_source_data_flows(end_point)
      @source_data_flows[end_point]
    end

    def add_basic_block(block)
      @basic_blocks.push(block)
      block
    end

    def add_pass(pass, *args)
      @passes << pass.new(self, *args)
    end

    def decode
      ip_to_inst = {}
      ip = 0
      inst = previous = nil
      lines = @compiled_code.lines
      line = 1
      if lines.first == -1
        @definition_line = lines[1]
        line += 2
      end
      #p lines
      call_sites = @compiled_code.call_sites.to_a
      call_site_index = 0
      Rubinius::InstructionDecoder.new(@compiled_code.iseq).
                                       decode.
                                       collect do |stream|
        instruction = CompiledCode::Instruction.new(stream, @compiled_code, ip)
        op_code, *bytecodes = stream

        inst = ip_to_inst[ip] = Inst.new(instruction)
        if call_sites[call_site_index] and ip == call_sites[call_site_index].ip
          inst.call_site = call_sites[call_site_index]
          call_site_index += 1
        end
        if line
          if lines[line - 1] <= ip and ip < lines[line + 1]
            inst.line = lines[line]
          else
            line += 2
            if line < lines.size - 1
              if lines[line - 1] <= ip and ip < lines[line + 1]
                inst.line = lines[line]
              end
            else
              line = nil
            end
          end
        end
        if previous
          previous.following_instruction = inst
          inst.preceeding_instruction = previous
        else
          @entry_inst = EntryInst.new
          NextFlow.new(self, entry_inst, inst)
        end

        ip += instruction.size
        # ap inst.to_label(self)
        previous = inst
      end
      #ap ip_to_inst

      ip = 0
      @local_op_codes = {}
      @literal_op_codes = {}
      Rubinius::InstructionDecoder.new(@compiled_code.iseq).
                                   decode.
                                   each do |stream|
        inst = ip_to_inst[ip]
        op_code, *bytecodes = stream
        op_rands = inst.instruction.args.collect.with_index do |arg, index|
          bytecode = bytecodes[index]
          case op_code.args[index]
          when :count, :positions, :index, :depth
            if inst.op_code == :passed_arg
              Parameter.new(bytecode)
            else
              Count.new(bytecode)
            end
          when :local
            @local_op_codes[bytecode] ||= Local.new(bytecode)
          when :which
            StackLocal.new(bytecode)
          when :type
            Type.new(bytecode)
          when :location, :ip
            BranchFlow.new(self, inst, ip_to_inst[bytecode], bytecode)
          when :literal, :number
            @literal_op_codes[bytecode] ||= Literal.new(bytecode)
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
        if instruction.branch_flow? and (branch_flow = instruction.branch_flow)
          branch_instruction = stacks.delete(branch_flow.dst_inst) ||
                                 branch_flow.dst_inst
          stacks.push(branch_instruction)
        end

        if instruction
          if instruction.previous_flow && instruction != first_instruction
            rewinds = []
            previous = instruction.previous_inst
            while not used.include?(previous) and not previous.incoming_flows.empty? # remove empty future
              if rewinds.include?(previous)
                raise "detected recursive"
              end
              rewinds << previous
              #p previous.to_label(self)
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

      lines = []
      if @definition_line
        lines << -1
        lines << @definition_line
      end
      ip = 0
      line = first_instruction.line
      lines << ip
      lines << line
      sequence.each do |inst|
        inst.ip = ip
        if line != inst.line
          lines << ip
          lines << line
          line = inst.line
        end
        ip += inst.instruction_width
      end
      lines << ip

      bytecodes = []
      sequence.each do |inst|
        bytecodes << inst.bytecode
        inst.op_rands.each do |op_rand|
          bytecodes << op_rand.to_bytecode(inst)
        end
      end

      [bytecodes, lines]
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

      bytecodes, lines = generate_bytecode
      raise "too small, is there call flow analysis???" if bytecodes.size == 1

      #opted = OptimizedCode.new
      opted = CompiledCode.new
      opted.iseq = Rubinius::InstructionSequence.new(bytecodes.to_tuple)
      opted.literals = literals.to_tuple
      opted.lines = lines.to_tuple

      opted.required_args = @compiled_code.required_args
      opted.post_args = @compiled_code.post_args
      opted.total_args = @compiled_code.total_args
      opted.splat = @compiled_code.splat
      opted.block_index = @compiled_code.block_index
      opted.local_count = local_count
      opted.local_names = local_names.to_tuple
      #opted.name = :"_Z_#{@compiled_code.name}_#{bytecodes.size}"

      opted.stack_size = @compiled_code.stack_size
      opted.file = @compiled_code.file
      opted.name = @compiled_code.name
      opted.primitive      = @compiled_code.primitive

      if @compiled_code.is_block?
        opted.add_metadata :for_block, true
      end

      if @compiled_code.for_module_body?
        opted.add_metadata :for_module_body, true
      end

      #opted.original_code = @compiled_code
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
      class OpRand
        attr_reader :instruction
        def initialize(instruction)
          @instruction = instruction
        end

        def to_inst
          @instruction
        end
      end

      class Self < OpRand
        def to_label(optimizer)
          "<self>"
        end
      end

      class Exit < OpRand
        def to_label(optimizer)
          "<exit>"
        end
      end

      class Void < OpRand
        def to_label(optimizer)
          "<void>"
        end
      end

      class Receiver < OpRand
        def to_label(optimizer)
          "recv"
        end
      end

      class Block < OpRand
        def to_label(optimizer)
          "block"
        end
      end

      class Object < OpRand
        def to_label(optimizer)
          "object"
        end
      end

      class Class < OpRand
        def to_label(optimizer)
          "class"
        end
      end

      class Argument < OpRand
        def initialize(index, instruction)
          super(instruction)
          @index = index
        end

        def to_label(_optimizer)
          "arg#{@index - 1}"
        end
      end

      class Shuffle < OpRand
        attr_reader :instruction
        def initialize(index, instruction, type)
          super(instruction)
          @index = index
          @type = type
        end

        def to_label(_optimizer)
          case @type
          when :import
            "port#{@index}i"
          when :export
            "port#{@index}o"
          else
            raise
          end
        end
      end

      attr :source, :sink
      def initialize(optimizer, source, sink)
        @source = source
        @sink = sink
        install(optimizer)
      end

      def inst
      end

      def install(optimizer)
        optimizer.source_data_flows[source.to_inst] << self
        optimizer.sink_data_flows[sink.to_inst] << self
        optimizer.data_flows.push(self)
      end

      def uninstall(optimizer)
        optimizer.source_data_flows[source.to_inst].delete(self)
        optimizer.sink_data_flows[sink.to_inst].delete(self)
        optimizer.data_flows.delete(self)
      end
    end

    class MoveDownRemover < Optimization
      def optimize
        optimizer.each_instruction do |instruction|
          if instruction.op_code == :move_down
            consumers = optimizer.find_source_data_flows(instruction.exports.first)
            next if consumers.size != 1
            consumer = consumers.first.sink
            next if not consumer.is_a?(Inst) or consumer.op_code != :pop
            producers = optimizer.find_sink_data_flows(instruction.imports.last)
            next if producers.size != 1
            producer = producers.first.source
            next if not producer.is_a?(DataFlow::Shuffle) or producer.instruction.op_code != :dup_top
            dup_top = producer.instruction
            move_down = instruction
            pop = consumer
            next unless (dup_top.previous_flow && dup_top.incoming_branch_flows.empty? and
                         move_down.previous_flow && move_down.incoming_branch_flows.empty? and
                         pop.previous_flow && pop.incoming_branch_flows.empty?)

            dup_top.mark_raw_remove
            move_down.mark_raw_remove
            pop.mark_raw_remove

            dup_top.previous_flow.change_dst_inst(move_down.next_flow.dst_inst)
            pop.previous_flow.change_dst_inst(pop.next_flow.dst_inst)

            optimizer.remove_flow(dup_top.next_flow.mark_remove.uninstall)
            optimizer.remove_flow(move_down.next_flow.mark_remove.uninstall)
            optimizer.remove_flow(pop.next_flow.mark_remove.uninstall)

            dup_top.raw_remove
            move_down.raw_remove
            pop.raw_remove
          end
        end
      end
    end

    class GeneratorWrapper
      include GeneratorMethods
      def initialize
        @current_block = self
      end

      def emit_push_literal(arg1)
        @current_block.add_stack(0, 1)
      end
      alias_method :push_literal, :emit_push_literal

      def add_stack(read, write)
        [read, write]
      end

    end
    W = GeneratorWrapper.new

    class BasicBlock
      attr_accessor :branch_block, :next_block
      attr_reader :stack, :min_size, :max_size
      def initialize(analyzer)
        @analyzer = analyzer
        @instructions = []
        @branch_block = @next_block = nil
        @max_size = @min_size = @stack = 0
        @closed = false
        @visited = false
        @exit_size = nil
      end

      def close(record_exit=false)
        @closed = true

        if record_exit
          @exit_size = @stack
        end
      end

      def closed?
        @closed
      end

      def visited?
        @visited
      end

      def add_instruction(instruction)
        read, write = W.send(instruction.op_code, *instruction.op_rands)
        add_stack(read.to_i, write.to_i)
        @instructions.push(instruction)
      end

      def add_stack(read, write)
        read_change = @stack - read
        @min_size = read_change if read_change < @min_size

        @stack += (write - read)

        @max_size = @stack if @stack > @max_size
      end

      def to_label(optimizer)
        (
          ["#{closed? ? "CLOSED " : ""}#{@exit_size ? "exit_size: #{@exit_size} " : ""}enter_size: #{@enter_size}, stack: #{@stack}, min: #{@min_size}, max: #{@max_size}"] +
          (@instructions.collect do |instruction|
            instruction.to_label(optimizer)
          end)
        ).join("\n")
      end

      def validate_stack
        @enter_size = 0
        stack = [self]
        until stack.empty?
          bb = stack.shift
          bb.flow_stack_size stack
        end
      end

      def flow_stack_size(stack)
        unless @visited
          @visited = true

          @analyzer.accumulate_stack(@enter_size + @max_size)

          net_size = @enter_size + @stack

          if net_size < 0
            invalid "net stack underflow"
          end

          if @enter_size + @min_size < 0
            invalid "minimum stack underflow"
          end

          if @exit_size and @enter_size + @exit_size < 1
            invalid "exit stack underflow"
          end

          if @next_block
            @next_block.check_stack net_size
            stack.push @next_block unless @next_block.visited?
          end

          if @branch_block
            @branch_block.check_stack net_size
            stack.push @branch_block unless @branch_block.visited?
          end
        end
      end

      def check_stack(stack_size)
        if defined?(@enter_size)
          unless stack_size == @enter_size
            invalid "unbalanced stack at stack_size != enter_size: #{stack_size} != #{@enter_size}"
          end
        else
          if not closed?
            invalid "control fails to exit properly"
          end

          @enter_size = stack_size
        end
      end

      def invalid(message)
        puts
        puts "INVALID:"
        puts to_label(nil)
        raise message
      end
    end

    class StackAnalyzer < Analysis
      def optimize
        optimizer.basic_blocks.clear
        optimizer.max_stack_size = @max_stack = 0

        pending_flows = [optimizer.first_flow]
        blocks = {}

        until pending_flows.empty?
          flow = pending_flows.shift
          current = (blocks[flow.dst_inst] ||= create_block)

          while flow
            instruction = flow.dst_inst

            if not instruction.incoming_branch_flows.empty?
              if not blocks.has_key?(instruction)
                new_block = (blocks[instruction] ||= create_block)
                current.close
                current.next_block = new_block
                optimizer.exit_flows << flow
                current = new_block
              elsif current != blocks[instruction]
                current.close
                current.next_block = blocks[instruction]
                optimizer.exit_flows << flow
                break
              end
            end

            current.add_instruction(flow.dst_inst)

            case instruction.op_code
            when :goto
              if not blocks.has_key?(instruction.branch_flow.dst_inst)
                pending_flows.push(instruction.branch_flow)
              end
              new_block = (blocks[instruction.branch_flow.dst_inst] ||= create_block)
              current.branch_block = new_block
              current.close
              flow = nil
            when :goto_if_true, :goto_if_false, :setup_unwind
              if not blocks.has_key?(instruction.branch_flow.dst_inst)
                pending_flows.push(instruction.branch_flow)
              end
              new_block = (blocks[instruction.branch_flow.dst_inst] ||= create_block)
              current.branch_block = new_block
              current.close
              if not blocks.has_key?(instruction.next_flow.dst_inst)
                pending_flows.push(instruction.next_flow)
                new_block = (blocks[instruction.next_flow.dst_inst] ||= create_block)
                current.next_block = new_block
              end
              flow = nil
            else
              if instruction.flow_type == :return
                current.close(true)
                optimizer.exit_flows << flow
                flow = nil
              elsif instruction.flow_type == :raise
                if instruction.op_code == :raise_return or
                   instruction.op_code == :ensure_return
                  current.close(true)
                  optimizer.exit_flows << flow
                else
                  current.close
                end
                flow = nil
              else
                flow = instruction.next_flow
              end
            end
          end
        end

        validate_stack
        #puts ["max stack", @max_stack].inspect
        optimizer.max_stack_size = @max_stack
      end

      def validate_stack
        optimizer.basic_blocks.first.validate_stack
      end

      def create_block
        optimizer.add_basic_block(BasicBlock.new(self))
      end

      def accumulate_stack(size)
        @max_stack = size if size > @max_stack
      end
    end

    class StackPrinter < Analysis
      def initialize(*args, file, &block)
        super(*args, &block)
        @file = file
      end

      def base_name
        if @file
          "/tmp/stack_#{@file}"
        else
          "/tmp/stack"
        end
      end

      def optimize
        @g = GraphViz.new(:G, :type => :digraph)
        @g[:rankdir] = "LR"
        flags = {}

        optimizer.basic_blocks.each do |block|
          node = @g.add_nodes(block_node(block))
          if block.next_block
            edge = @g.add_edges(block_node(block), block_node(block.next_block))
            edge.label = "next_block"
          end
          if block.branch_block
            edge = @g.add_edges(block_node(block), block_node(block.branch_block))
            edge.label = "branch_block"
          end
        end

        @g.output(:pdf => "#{base_name}.pdf")
      end

      def block_node(block)
        block.to_label(optimizer)
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
          if not previous.nil? and (previous.op_code == :goto or previous.flow_type == :return or previous.flow_type == :raise)
            #puts stacks.size
            #puts previous.to_label(nil)
            #puts main_stack.map{|a| a.to_label(optimizer) }
            if(instruction.incoming_flows.all? do |goto|
              goto.src_inst != previous
            end)
              #stacks.clear
            end
            #stacks.reject!{|s| s.equal?(main_stack)}
            #puts stacks.size
          end
          instruction.incoming_branch_flows.each do |goto|
            if goto.src_inst.op_code == :goto or
               goto.src_inst.op_code == :goto_if_true or
               goto.src_inst.op_code == :goto_if_false or
               goto.src_inst.op_code == :setup_unwind
              branch_target_found = true
              #puts "aadding stack"
              #puts goto.src_inst.to_label(optimizer)
              stacks << goto_to_stack[goto.src_inst] if goto_to_stack.has_key?(goto.src_inst)
            end
          end
          if not previous.nil? and (previous.op_code == :goto or previous.flow_type == :return or previous.flow_type == :raise)
            if not branch_target_found and stacks.all?(&:empty?)
              previous = instruction
              next
            end
          end

          stacks.each do |other_stack|
            stacks.delete(other_stack) if other_stack and other_stack.empty?
          end

          if stacks.empty?
            main_stack = []
            stacks = [main_stack]
          end
          stacks.uniq!
          #p instruction.to_label(nil)
          #ap stacks.map{|s| s.map{|m| m.to_label(optimizer) } }
          stacks.each.with_index do |stack, stack_index|
            case instruction.op_code
            when :goto_if_true, :goto_if_false, :goto, :setup_unwind
              stk = stack.dup
              if instruction.op_code != :goto and instruction.op_code != :setup_unwind
                raise "underflow" if stk.empty?
                stk.pop
                #p instruction
                #ap stk, raw: true
              else
                #p stk.map{|a| a.to_label(optimizer) }
              end
              goto_to_stack[instruction] = stk unless stk.empty?
            when :push_self
              DataFlow.new(optimizer, DataFlow::Self.new(instruction), instruction)
            when :push_local, :push_literal, :push_const_fast, :push_ivar, :find_const_fast, :passed_arg
              instruction.op_rands.each do |op_rand|
                DataFlow.new(optimizer, op_rand, instruction)
              end
            when :set_local, :set_literal, :set_const_fast, :set_ivar
              instruction.op_rands.each do |op_rand|
                DataFlow.new(optimizer, instruction, op_rand)
              end
            when :pop
              DataFlow.new(optimizer, instruction, DataFlow::Void.new(instruction))
            else
              if instruction.flow_type == :return or instruction.flow_type == :raise
                DataFlow.new(optimizer, instruction, DataFlow::Exit.new(instruction))
              end
            end

            case instruction.op_code
            when :send_stack
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                if index.zero?
                  source = stack.pop
                  receiver = DataFlow::Receiver.new(instruction)
                  instruction.imports.unshift(receiver) if stack_index.zero?
                  DataFlow.new(optimizer, source, receiver)
                else
                  source = stack.pop
                  arg = DataFlow::Argument.new(index, instruction)
                  instruction.imports.unshift(arg) if stack_index.zero?
                  DataFlow.new(optimizer, source, arg)
                end
              end
            when :swap_stack
              source = stack.pop
              shuffle1 = DataFlow::Shuffle.new(1, instruction, :import)
              DataFlow.new(optimizer, source, shuffle1)

              source = stack.pop
              shuffle2 = DataFlow::Shuffle.new(0, instruction, :import)
              DataFlow.new(optimizer, source, shuffle2)

              instruction.imports.unshift(shuffle1) if stack_index.zero?
              instruction.imports.unshift(shuffle2) if stack_index.zero?
            when :kind_of
              source = stack.pop
              shuffle = DataFlow::Class.new(instruction)
              instruction.imports.unshift(shuffle) if stack_index.zero?
              DataFlow.new(optimizer, source, shuffle)

              source = stack.pop
              shuffle = DataFlow::Object.new(instruction)
              instruction.imports.unshift(shuffle) if stack_index.zero?
              DataFlow.new(optimizer, source, shuffle)
            when :move_down
              (instruction.stack_consumed + 1).times.to_a.reverse.each do |index|
                source = stack.pop
                shuffle = DataFlow::Shuffle.new(index, instruction, :import)
                instruction.imports.unshift(shuffle) if stack_index.zero?
                DataFlow.new(optimizer, source, shuffle)
              end
            when :rotate
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                source = stack.pop
                shuffle = DataFlow::Shuffle.new(index, instruction, :import)
                instruction.imports.unshift(shuffle) if stack_index.zero?
                DataFlow.new(optimizer, source, shuffle)
              end
            when :dup_many
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                source = stack.pop
                shuffle = DataFlow::Shuffle.new(index, instruction, :import)
                instruction.imports.unshift(shuffle) if stack_index.zero?
                DataFlow.new(optimizer, source, shuffle)
              end
            when :make_array
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                source = stack.pop
                shuffle = DataFlow::Shuffle.new(index, instruction, :import)
                instruction.imports.unshift(shuffle) if stack_index.zero?
                DataFlow.new(optimizer, source, shuffle)
              end
            when :send_stack_with_block
              instruction.stack_consumed.times.to_a.reverse.each do |index|
                if index == 0
                  source = stack.pop
                  receiver = DataFlow::Receiver.new(instruction)
                  instruction.imports.unshift(receiver) if stack_index.zero?
                  DataFlow.new(optimizer, source, receiver)
                elsif index == instruction.stack_consumed - 1
                  source = stack.pop
                  receiver = DataFlow::Block.new(instruction)
                  instruction.imports.unshift(receiver) if stack_index.zero?
                  DataFlow.new(optimizer, source, receiver)
                else
                  source = stack.pop
                  arg = DataFlow::Argument.new(index, instruction)
                  instruction.imports.unshift(arg) if stack_index.zero?
                  DataFlow.new(optimizer, source, arg)
                end
              end
            else
              #puts stacks.size
              #puts instruction.to_label(nil)
              instruction.stack_consumed.times do
                DataFlow.new(optimizer, stack.pop, instruction)
              end
            end
            #puts
            #p instruction
            #p instruction.stack_produced
            #  p instruction.op_code
            if instruction.op_code == :move_down
              exports = Array.new(instruction.stack_produced)
              i = 0
              (instruction.stack_produced + 1).times.to_a.rotate(-1).each do |index|
                shuffle = DataFlow::Shuffle.new(index, instruction, :export)
                exports[i] = shuffle
                i += 1
              end
              #p exports.size
              exports.each do |export|
                instruction.exports.push(export) if stack_index.zero?
                stack.push(export)
              end
            elsif instruction.op_code == :dup_many
              2.times.to_a.each do |repeat|
                (instruction.stack_produced / 2).times.to_a.each do |index|
                  label = "#{index}_#{"abcdefg"[repeat]}"
                  shuffle = DataFlow::Shuffle.new(label, instruction, :export)
                  instruction.exports.push(shuffle) if stack_index.zero?
                  stack.push(shuffle)
                end
              end
            elsif instruction.op_code == :rotate
              instruction.stack_produced.times.each do |index|
                shuffle = DataFlow::Shuffle.new(index, instruction, :export)
                instruction.exports.unshift(shuffle) if stack_index.zero?
                stack.push(shuffle)
              end
            elsif instruction.op_code == :swap_stack
              instruction.stack_produced.times.to_a.reverse.each do |index|
                shuffle = DataFlow::Shuffle.new(index, instruction, :export)
                instruction.exports.unshift(shuffle) if stack_index.zero?
                stack.push(shuffle)
              end
            elsif instruction.op_code == :dup_top
              instruction.stack_produced.times.each do |index|
                shuffle = DataFlow::Shuffle.new(index, instruction, :export)
                instruction.exports.push(shuffle) if stack_index.zero?
                stack.push(shuffle)
              end
            else
              instruction.stack_produced.times do
                stack.push(instruction)
              end
            end
          end
          previous = instruction
        end
      end
    end

    class DataFlowPrinter < Analysis
      def initialize(*args, file, &block)
        super(*args, &block)
        @file = file
      end

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
            #puts data_flow.sink.to_label(optimizer)
            source_node = decorate_node(data_flow.source)
          end

          flag_key = [source_node, sink_node]
          flags[flag_key] || @g.add_edges(source_node, sink_node)
          flags[flag_key] = true
        end

        @g.output(:pdf => "#{base_name}.pdf")
        raise "failed" if $FAIL
      end

      def base_name
        if @file
          "/tmp/data_flow_#{@file}"
        else
          "/tmp/data_flow"
        end
      end

      def escape(text)
        text.gsub(/</, "\\<").gsub(/>/, "\\>")
      end

      def decorate_node(data)
        unless data
          puts optimizer.compiled_code.inspect
          $FAIL = true
          return "NIL"
        end

        suffix = nil #"(branch_flow)" if data.respond_to?(:incoming_branch_flows) and not data.incoming_branch_flows.empty?
        if data.is_a?(Inst) and (not data.imports.empty? or not data.exports.empty?)
          node = @g.get_node(data.to_label(optimizer)) || @g.add_nodes(data.to_label(optimizer))
          label = escape(data.to_label(optimizer))

          imports = data.imports.collect do |import|
            if import.is_a?(DataFlow::Shuffle)
              port = "#{import.to_label(optimizer)}"
              "<#{port}>#{escape(import.to_label(optimizer).gsub(/i$/,''))}"
            else
              port = import.to_label(optimizer)
              "<#{port}>#{escape(import.to_label(optimizer))}"
            end
          end.join("|")
          imports = "{#{imports}}|" unless imports.empty?

          exports = data.exports.collect do |export|
            if export.is_a?(DataFlow::Shuffle)
              port = "#{export.to_label(optimizer)}"
              "<#{port}>#{escape(export.to_label(optimizer).gsub(/o$/,''))}"
            else
              port = export.to_label(optimizer)
              "<#{port}>#{escape(export.to_label(optimizer))}"
            end
          end.join("|")
          exports = "|{#{exports}}" unless exports.empty?

          node.label = "{#{imports}#{label}#{suffix}#{exports}}"
          node.shape = 'record'
          node.style = 'dashed' if data.is_a?(Inst) and data.mark_for_removal?
          node.fontname = 'M+ 1mn'
        else
          node = @g.get_node(label = data.to_label(optimizer)) || @g.add_nodes(label = data.to_label(optimizer))
          node.label = "#{label}#{suffix}"

          if data.is_a?(Endpoint)
            node.shape = 'rect'
          else
            node.shape = 'round'
          end

          node.style = 'dashed' if data.is_a?(Inst) and data.mark_for_removal?
          node.fontname = 'M+ 1mn'
        end
        node
      end
    end

    class Flow
      attr_reader :src_inst, :dst_inst, :spots, :previous_spots
      def initialize(optimizer, src_inst, dst_inst)
        @src_inst = src_inst
        raise "src_inst is nil: #{@dst_inst.to_label(nil) if @dst_inst}" if @src_inst.nil?
        @dst_inst = dst_inst
        raise "dst_inst is nil: src: #{@src_inst.to_label(nil)}" if @dst_inst.nil?
        @remove = false
        @installed = false
        @spots = []
        @previous_spots = []
        @metadata = {}
        @optimizer = optimizer
        install
      end

      def add_flow(flow)
        flow
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
        @optimizer.flows.push(self)
        @installed = true
        self
      end

      def uninstall
        raise "double uninstallation" if not @installed
        @optimizer.flows.delete(self)
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

      def change_src_inst(src_inst)
        change_src_dst(src_inst, dst_inst)
      end

      def change_dst_inst(dst_inst)
        change_src_dst(src_inst, dst_inst)
      end
    end

    class NextFlow < Flow
      def type
        :next
      end

      def dynamic_dst?
        if @src_inst.is_a?(EntryInst)
          true
        else
          false
        end
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
      def initialize
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

    class BranchFlow < Flow
      def initialize(optimizer, src_inst, dst_inst, bytecode)
        raise "not branch instruction" if src_inst.flow_type == :next
        super(optimizer, src_inst, dst_inst)
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
      def optimize
        previous = nil
        optimizer.each_instruction do |instruction|
          if previous and
             previous.op_code != :goto and
             previous.flow_type != :return and
             previous.flow_type != :raise
            NextFlow.new(optimizer, previous, instruction)
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
          #labels += [flow.src_inst.to_s]
          #labels += [[flow.src_inst.incoming_flows.collect(&:src_inst)].to_s.split(", ").join("\n")]
          if not labels.empty?
            edge.label = labels.join("\n")
            edge.fontname = 'monospace'
            edge.fontsize = '11'
          end
          edge.style = 'dashed' if flow.mark_removed?
        end

        g.output(:pdf => "#{base_name}.pdf")
        #g.output(:ps => "flow.ps")
        #g.output(:svg => "#{base_name}.svg")
      end

      def base_name
        if @file
          "/tmp/flow_#{@file}"
        else
          "/tmp/flow"
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
      attr_reader :inst, :states
      def initialize(inst, states)
        @inst = inst
        @states = states
      end

      def to_label(optimizer)
        "restore from #{@inst.to_label(nil)}"
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

      attr_reader :optimizer
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

    class RepeatedPush < Matcher
      before [
        :push_nil,
        :set_local,
        :pop,
        :push_nil,
        :set_local,
        :pop,
      ]
    end

    class CheckFrozen < Matcher
      before [
        [:check_frozen],
        [:pop],
        [:push_self],
      ]

      after [
        [:check_frozen],
      ]

      def type
        :check_frozen
      end
    end

    class NilRemover < Matcher
      before [
        [:push_nil],
        :no_stack_changes,
        [:pop],
      ]

      after [
        :no_stack_changes,
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

          if forwardable?
            raise "bad" if flows.size != 2
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

      def forwardable?
        forwardable = false
        @results.each do |previous_flow, flow, match|
          unless @matcher.class.translator.include?(match)
            next_flow = flow
            while next_flow = next_flow.dst_inst.static_next_flow
              if next_flow.spots == [self]
                forwardable = true
              elsif not next_flow.spots.empty?
                return false
              end
            end
          end
        end

        forwardable
      end

      def not_isolated?
        if not defined?(@isolation_calculated)
          # this is bad
          true
        else
          not @isolation
        end
      end

      def isolated?
        @isolation_calculated = true
        @isolation ||= do_isolated?
      end

      def do_isolated?
        @results[1..-1].each do |previous_flow, flow, match|
          unless @matcher.class.translator.include?(match)
            if flow.dst_inst.incoming_flows.size > 1
              comparison = flow.dst_inst.incoming_flows.collect do |incoming_flow|
                return false if incoming_flow !=flow and incoming_flow.spots.any?(&:not_isolated?)

                [
                incoming_flow.spots.map(&:type),
                incoming_flow.spots.map{|s| s.position(incoming_flow) },
                ]
              end
              if comparison.uniq.size > 1
                return false
              end
            end
          else
            if flow.dst_inst.incoming_flows.size > 1
              return false
            end
          end
        end

        true
      end
    end

    class PassedArg < Matcher
      class Spot < Optimizer::Spot
        def optimizer
          @matcher.optimizer
        end

        def transform
          to_passed_arg, to_goto_if_true, to_push_nil, to_set_local, to_pop = @flows
          optimizer.remove_flow(to_passed_arg.mark_remove)
          #to_passed_arg.change_dst_inst(to_pop.dst_inst.next_flow.dst_inst)
          optimizer.remove_flow to_goto_if_true.mark_remove
          optimizer.remove_flow to_goto_if_true.dst_inst.branch_flow.mark_remove
          optimizer.remove_flow to_push_nil.mark_remove
          optimizer.remove_flow to_set_local.mark_remove
          optimizer.remove_flow to_pop.mark_remove
          next_inst = to_pop.dst_inst.next_flow.dst_inst
          #next_inst.incoming_branch_flows.each do |flow|
            #flow.change_src_inst(to_passed_arg.src_inst)
          #end
          to_passed_arg.dst_inst.incoming_flows.dup.each do |flow|
            next if flow == to_passed_arg
            #flow.mark_remove
            flow.change_dst_inst(next_inst)
          end
          to_pop.dst_inst.next_flow.change_src_inst(to_passed_arg.src_inst)
          to_passed_arg.dst_inst.raw_remove
          to_goto_if_true.dst_inst.raw_remove
          to_push_nil.dst_inst.raw_remove
          to_set_local.dst_inst.raw_remove
          to_pop.dst_inst.raw_remove
          #raise "overridden"
        end
      end

      before [
        [:passed_arg],
        [:goto_if_true],
        [:push_nil],
        [:set_local],
        [:pop],
      ]

      after [
      ]

      def create_spot(results)
        Spot.new(self, results)
      end

      def type
        :passed_arg
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
              #p inst.op_code
              if INTERRUPTABLE_INSTRUCTIONS.include?(inst.op_code)
                removable = true
                break
              end
              inst = inst.previous_inst
            end
            if removable
              #p :ok_removala
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
                #puts "goto / goto if true"
                #puts incoming_flow.src_inst.incoming_flows.size
                #incoming_flow.point_to_next_instruction
              elsif incoming_flow.src_inst.op_code == :goto_if_false
                #incoming_flow.point_to_next_instruction
                #p inst.previous
                if incoming_flow.src_inst.next_flow == inst.previous_flow and
                   inst.incoming_flows.size == 1
                  #puts "goto / goto if false next"
                  goto_if_false = incoming_flow.src_inst
                  goto = inst
                  if goto.branch_flow.dst_inst.instruction.ip < goto.instruction.ip
                    next
                  end

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
                  #puts "goto / goto if false branch"
                  goto_if_false = incoming_flow.src_inst
                  goto = inst
                  goto_if_false.branch_flow.change_dst_inst(goto.branch_flow.dst_inst)
                  #puts incoming_flow.src_inst.incoming_flows.size
                  #incoming_flow.src_inst.branch_flow.reinstall do
                  #  incoming_flow.src_inst.branch_flow.instance_variable_set(:@dst_inst, inst.branch_flow.dst_inst)
                  #end
                  #optimizer.remove_flow(inst.branch_flow)
                end
              elsif incoming_flow.src_inst.op_code == :goto
                #puts "goto / goto"
                first_goto = incoming_flow.src_inst
                second_goto = inst
                first_goto.branch_flow.change_dst_inst(second_goto.branch_flow.dst_inst)
                #puts inst
                #puts incoming_flow.src_inst.incoming_flows.size
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
                  raise "recently untested"
                  new_inst = inst.dup
                  optimizer.remove_flow(inst.static_next_flow)
                  inst.raw_remove
                  after_inst = branch_flow.src_inst
                  after_inst.previous_flow.change_src_dst(after_inst.previous_flow.src_inst, new_inst)

                  branch_flow.point_to_next_instruction
                  branch_flow.unmark_remove
                  NextFlow.new(optimizer, new_inst, after_inst)
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
              @states = event.states.collect(&:take_snapshot)
              #p event
              #reset
            when Terminate
              #ap @states.collect(&:take_snapshot)
              #push
              #p event
            else
              #p event.compact.map{|i| i.to_label(optimizer)}
              #p event.last.dst_inst.to_label(@optimizer)
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
          #RepeatedPush.new(optimizer, self),
          NilRemover.new(optimizer, self),
          #InfiniteLoop.new(optimizer, self),
          #PassedArg.new(optimizer, self),
          #CheckFrozen.new(optimizer, self),
        ]
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
          previous, current, event = stack.pop

          if event
            yield event
          end

          while current
            if current.dst_inst.flow_type == :branch
              if loop_marks[current].nil?
                loop_marks[current] = true
                if current.dst_inst.next_flow
                  stack.push([current, current.dst_inst.branch_flow, Restore.new(current.dst_inst, @states)])
                  stack.push([current, current.dst_inst.next_flow, Restore.new(current.dst_inst, @states)])
                  yield_flow(previous, current, &block)
                  previous = current
                  current = nil
                else
                  yield_flow(previous, current, &block)
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
              yield_flow(previous, current, &block)
              previous = current
              current = current.dst_inst.next_flow
            end
          end
        end
        yield Terminate.new
      end

      def yield_flow(previous, current)
        yield([previous, current])
      end
    end

    class Inliner < Optimization
      def optimize
        optimizer.each_instruction do |instruction|
          case instruction.op_code
          when :send_stack
            send_stack = instruction
            sources = optimier.find_soure_data_flows(send_stack)
            raise sources.inspect
            if send_stack.call_site.is_a?(MonoInlineCache)
              code = send_stack.call_site.method
              if code.name == :StringValue
                p code.name

                opt = Rubinius::Optimizer.new(code)
                opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
                opt.add_pass(Rubinius::Optimizer::StackAnalyzer)
                opt.add_pass(Rubinius::Optimizer::FlowPrinter, "inlined")
                opt.add_pass(Rubinius::Optimizer::StackPrinter, "inlined")
                opt.run
                if opt.signature == send_stack.signature
                  required, _post, _total, _splat, _block_index = opt.signature
                  offset = optimizer.local_count
                  optimizer.merge(opt)

                  prologue = opt.first_instruction
                  prev_inst = nil

                  arg_entry = nil
                  inst = nil
                  required.times do |index|
                    arg_entry ||= old_inst = inst = Inst.new(nil)
                    bytecode = InstructionSet.opcodes_map[:set_local]
                    op_code = InstructionSet.opcodes[bytecode]
                    inst.instruction_width = op_code.width
                    inst.bytecode = bytecode
                    inst.op_rands = [Local.new(offset +  index)]
                    inst.op_code = :set_local
                    inst.flow_type = op_code.control_flow
                    inst.label = "set local"

                    inst = Inst.new(nil)
                    bytecode = InstructionSet.opcodes_map[:pop]
                    op_code = InstructionSet.opcodes[bytecode]
                    inst.instruction_width = op_code.width
                    inst.bytecode = bytecode
                    inst.op_rands = []
                    inst.op_code = :pop
                    inst.flow_type = op_code.control_flow
                    inst.label = "pop local"
                    NextFlow.new(optimizer, old_inst, inst)

                    if prev_inst
                      NextFlow.new(optimizer, prev_inst, inst)
                    end
                    prev_inst = inst
                  end
                  if inst
                    NextFlow.new(optimizer, inst, prologue)
                    prologue = arg_entry
                  end

                  p code.local_names
                  send_stack.incoming_flows.each do |flow|
                    flow.change_dst_inst(prologue)
                  end
                  opt.exit_flows.each do |exit_flow|
                    exit_flow.change_dst_inst(send_stack.next_flow.dst_inst)
                  end
                end
              end
            end
          end
        end
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

if __FILE__ == $0

require 'graphviz'
require "pp"

#code = Rubinius::Optimizer::Inst.instance_method(:stack_consumed).executable
#code = File.method(:absolute_path).executable

class M
  def []=(index, other)
  end
end

def loo(aa)
  ((true) ? self : aa).hello
end
#code = Array.instance_method(:set_index).executable
#code = Array.instance_method(:bottom_up_merge).executable
#code = method(:loo).executable
#code = "".method(:dump).executable
#code = "".method(:[]).executable
#code = "".method(:start_with?).executable
#code = "".method(:start_with?).executable
#code = Enumerable.instance_method(:minmax).executable
#code = Time.method(:at).executable
#code = [].method(:|).executable
#code = [].method(:equal?).executable
#code = [].method(:cycle).executable
#code = ARGF.method(:each_line).executable
#code = IO::StreamCopier.instance_method(:run).executable
code = "".method(:+).executable
#code = IO.instance_method(:each).executable
#code = IO.method(:binwrite).executable
#code = Hash.instance_method(:reject).executable
#code = Integer.instance_method(:upto).executable
#code = Integer.instance_method(:round).executable
#code = Regexp.method(:escape).executable
#code = Rational.instance_method(:/).executable
#code = Rubinius::Loader.instance_method(:script).executable
#code = Rubinius::CodeLoader.method(:initialize).executable
opt = Rubinius::Optimizer.new(code)
puts code.decode.size
opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
opt.add_pass(Rubinius::Optimizer::FlowPrinter, "original")
opt.add_pass(Rubinius::Optimizer::PruneUnused)
opt.add_pass(Rubinius::Optimizer::StackAnalyzer)
opt.add_pass(Rubinius::Optimizer::StackPrinter, "original")
opt.add_pass(Rubinius::Optimizer::Inliner)
opt.add_pass(Rubinius::Optimizer::FlowPrinter, "after")
opt.add_pass(Rubinius::Optimizer::StackAnalyzer)
opt.add_pass(Rubinius::Optimizer::StackPrinter, "after")
opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
opt.add_pass(Rubinius::Optimizer::DataFlowPrinter, "after")
#opt.add_pass(Rubinius::Optimizer::PruneUnused)
#opt.add_pass(Rubinius::Optimizer::ScalarTransform)
#opt.add_pass(Rubinius::Optimizer::Prune)
#opt.add_pass(Rubinius::Optimizer::GotoRet)
#opt.add_pass(Rubinius::Optimizer::GoToRemover)
#opt.add_pass(Rubinius::Optimizer::PruneUnused)
#opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
#opt.add_pass(Rubinius::Optimizer::MoveDownRemover)
#opt.add_pass(Rubinius::Optimizer::DataFlowPrinter, "original")
#opt.add_pass(Rubinius::Optimizer::FlowPrinter, "generated")
#opt.add_pass(Rubinius::Optimizer::FlowPrinter, "generated")
#opt.add_pass(Rubinius::Optimizer::RemoveCheckInterrupts) # this hinders jit
#opt.add_pass(Rubinius::Optimizer::FlowAnalysis)

optimized_code = opt.run

opt = Rubinius::Optimizer.new(code)
opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
un_code = opt.run
puts un_code.decode.size

#if ENV["opt"] == "true"
#  code = optimied_code
#else
#  code = un_code
#end

opt = Rubinius::Optimizer.new(optimized_code)
opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
opt.add_pass(Rubinius::Optimizer::PruneUnused)
opt.add_pass(Rubinius::Optimizer::ScalarTransform)
opt.add_pass(Rubinius::Optimizer::Prune)
opt.add_pass(Rubinius::Optimizer::PruneUnused)
opt.add_pass(Rubinius::Optimizer::FlowPrinter, "generated")
opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
opt.add_pass(Rubinius::Optimizer::DataFlowPrinter, "generated")
opt.add_pass(Rubinius::Optimizer::StackAnalyzer)
opt.add_pass(Rubinius::Optimizer::StackPrinter, "generated")
optimized_code = opt.run
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
arg = []

#p result
puts

5.times do
  puts optimized_code.decode.size
  puts un_code.decode.size
  optimized_time = 0
  5.times do
    optimized_time += measure do
      10000.times do
        optimized_code.invoke(:loo, Array, hello, arg, nil)
      end
    end
  end
  unoptimized_time = 0
  5.times do
    unoptimized_time += measure do
      10000.times do
        un_code.invoke(:loo, Array, hello, arg, nil)
      end
    end
  end


  p "unoptimized: #{unoptimized_time}"
  p "optimized_time: #{optimized_time}"
  p "unopt/optimize: #{unoptimized_time/optimized_time}"
end
#p result
puts


p result

#return
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
end
