# -*- encoding: us-ascii -*-

module Rubinius
  class Slot
    attr_accessor :instruction, :basic_blocks, :jumps

    def initialize
      @instruction = nil
      @basic_blocks = []
      @jumps = []
    end

    def jump_from(instruction)
      @jumps << instruction
    end

    def materialize
      if @instruction
        @instruction[:ip]
      else
        100000
      end
    end
  end

  class InstructionList
    class Label
      attr_accessor :basic_block
      attr_reader :used
      alias_method :used?, :used

      def initialize(generator)
        @generator   = generator
        @basic_block = generator.new_basic_block

        @slot           = nil
        @used           = false
        @instruction    = nil
        @instructions   = nil
      end

      def set!
        @slot = @generator.ip

        if @instructions
          @instructions.each do |instruction|
            set_jump_slot(instruction)
          end
        elsif @instruction
          set_jump_slot(@instruction)
        end

        @generator.set_basic_block(@basic_block)
      end

      def used_at(instruction)
        if @slot
          set_jump_slot(instruction)
        elsif !@instruction
          @instruction = instruction
        elsif @instructions
          @instructions << instruction
        else
          @instructions = [@instruction, instruction]
        end
        @used = true
      end

      private
      def set_jump_slot(instruction)
        @slot.jump_from(instruction)
        instruction[:slot] = @slot
      end
    end

    class BasicBlock
      attr_accessor :left
      attr_accessor :right

      def initialize(generator)
        @generator  = generator
        @ip         = generator.ip
        @enter_size = nil
        @max_size   = 0
        @min_size   = 0
        @exit_ip    = 0
        @exit_size  = nil
        @stack      = 0
        @left       = nil
        @right      = nil
        @visited    = false
        @closed     = false
      end

      def add_stack(read, write)
        read_change = @stack - read
        @min_size = read_change if read_change < @min_size

        @stack += (write - read)

        @max_size = @stack if @stack > @max_size
      end

      def open
        @ip = @generator.ip
      end

      def close
        @closed = true
      end

      def close_and_exit(exit_instruction)
        close
        @exit_size = @stack
        @exit_ip = exit_instruction[:ip]
      end

      def location(ip=nil)
        ip ||= @ip
        line = nil #@generator.ip_to_line(ip)
        "#name: line: #{line}, IP: #{ip}"
      end

      SEPARATOR_SIZE = 40

      def invalid(message)
        raise CompileError, message
      end

      def visited?
        @visited
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

          @generator.accumulate_stack(@enter_size + @max_size)

          net_size = @enter_size + @stack

          if net_size < 0
            invalid "net stack underflow in block starting at #{location}"
          end

          if @enter_size + @min_size < 0
            invalid "minimum stack underflow in block starting at #{location}"
          end

          if @exit_size and @enter_size + @exit_size < 1
            invalid "exit stack underflow in block starting at #{location(@exit_ip)}"
          end

          if @left
            @left.check_stack net_size
            stack.push @left unless @left.visited?
          end

          if @right
            @right.check_stack net_size
            stack.push @right unless @right.visited?
          end
        end
      end

      def check_stack(stack_size)
        if @enter_size
          unless stack_size == @enter_size
            invalid "unbalanced stack at #{location}: #{stack_size} != #{@enter_size}"
          end
        else
          if not @closed
            invalid "control fails to exit properly at #{location}"
          end

          @enter_size = stack_size
        end
      end
    end

    def initialize
      @instruction_slots = [Slot.new]

      initialize_modifiers
      initialize_stack
    end

    attr_accessor :break, :redo, :next, :retry
    def initialize_modifiers
      @modstack = []
      @break = nil
      @redo = nil
      @next = nil
      @retry = nil
    end

    def push_modifiers
      @modstack << [@break, @redo, @next, @retry]
    end

    def pop_modifiers
      @break, @redo, @next, @retry = @modstack.pop
    end

    def empty?
      @instruction_slots.collect(&:instruction).compact.empty?
    end

    def initialize_stack
      @max_stack = 0
      @stack_locals = 0
    end

    def new_stack_local
      idx = @stack_locals
      @stack_locals += 1
      idx
    end

    def accumulate_stack(size)
      @max_stack = size if size > @max_stack
    end

    def max_stack_size
      @max_stack + @stack_locals
    end

    def create_instruction(name)
      instruction = {:name => name}
      @instruction_slots.last.instruction = instruction
      @instruction_slots << Slot.new
      instruction
    end

    def ip
      @instruction_slots.last
    end

    def set_basic_block(basic_block)
      @instruction_slots.last.basic_blocks << basic_block
    end

    def optimize
      #puts @instruction_slots.collect {|instruction| instruction[:name] }
      #puts
      last_slot = nil

      @instruction_slots.each_with_index do |slot, index|
        instruction = slot.instruction
        next if instruction.nil?

        last_instruction = last_slot.instruction if last_slot

        if last_instruction
          if instruction[:name] == :ret and
             last_instruction[:name] == :ret
            #p last_slot.basic_blocks.size
            #p slot.basic_blocks.size
            if last_slot.basic_blocks.empty? and slot.basic_blocks.empty?
              #p last_slot
              #p slot
              #puts "double ret"
              instruction[:remove] = true
            end
          end

          if instruction[:name] == :pop and
             last_instruction[:name] == :push_nil and
             slot.jumps.empty?
            next_slot = @instruction_slots[index + 1]

            jumps = last_slot.jumps
            jumps.each do |jump|
              jump[:slot] = next_slot
            end
            next_slot.jumps = jumps + next_slot.jumps
            last_slot.jumps.clear

            next_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks + next_slot.basic_blocks
            slot.basic_blocks.clear
            last_slot.basic_blocks.clear

            last_instruction[:remove] = true
            instruction[:remove] = true
          end
        end

        last_slot = slot
      end

      @instruction_slots.reject! do |slot|
        slot.instruction and slot.instruction[:remove]
      end
    end

    def materialize
      calculate_ip
      materialize_position
    end

    def calculate_ip
      ip = 0
      @instruction_slots.collect(&:instruction).compact.each do |instruction|
        instruction[:ip] = ip
        ip += instruction[:stream].size
      end
    end

    def replace_with_ip(instruction)
      basic_block = instruction[:stream][1]
      instruction[:stream][1] = instruction[:slot].materialize
      basic_block
    end

    def materialize_position
      @enter_block = current_block = new_basic_block

      @instruction_slots.each do |slot|
        instruction = slot.instruction
        next if instruction.nil?

        slot.basic_blocks.each do |basic_block|
          current_block.left = basic_block
          current_block.close
          current_block = basic_block
          current_block.open
        end

        if instruction[:name] != :cast_array
          current_block.add_stack(*instruction[:stack])
        end

        case instruction[:name]
        when :goto
          basic_block = replace_with_ip(instruction)

          current_block.left = basic_block
          current_block.close
          current_block = new_basic_block
        when :goto_if_false, :goto_if_true, :setup_unwind
          basic_block = replace_with_ip(instruction)

          current_block.left = basic_block
          current_block.close
          current_block = current_block.right = new_basic_block
        when :ret, :raise_return, :ensure_return
          current_block.close_and_exit instruction
          current_block = new_basic_block
        when :raise_exc, :reraise, :break
          current_block.close
          current_block = new_basic_block
        end
      end
    end

    def validate_stack
      #pp(@instruction_slots.collect(&:instruction).compact.collect do |instruction| {:ip => instruction[:ip], :name => instruction[:name], :stream => instruction[:stream]} end) if ENV["DEBUG"]
      begin
        # Validate the stack and calculate the max depth
        @enter_block.validate_stack
      rescue Exception => e
        if $DEBUG
          puts "Error computing stack for #{@name}: #{e.message} (#{e.class})"
        end
        require "pp"
        pp(@instruction_slots.collect(&:instruction).compact.collect do |instruction| {:ip => instruction[:ip], :name => instruction[:name], :stream => instruction[:stream]} end)
        raise e
      end
    end

    def iseq
      InstructionSequence.new(instruction_stream.to_tuple)
    end

    def new_basic_block
      BasicBlock.new(self)
    end

    def new_label
      Label.new(self)
    end

    private
    def instruction_stream
      stream = []
      @instruction_slots.collect(&:instruction).compact.collect do |instruction|
        stream += instruction[:stream]
      end
      stream
    end
  end

  module GeneratorMethods
    alias_method :dup,  :dup_top
    alias_method :git,  :goto_if_true
    alias_method :gif,  :goto_if_false
    alias_method :swap, :swap_stack

    def create_instruction(name)
      @instruction = @instruction_list.create_instruction(name)
    end

    def push(what)
      case what
      when :true
        push_true
      when :false
        push_false
      when :self
        push_self
      when :nil
        push_nil
      when Integer
        push_int what
      else
        raise CompileError, "Unknown push argument '#{what.inspect}'"
      end
    end

    def push_const(name)
      push_const_fast find_literal(name), add_literal(nil)
    end

    alias_method :__meta_to_s, :meta_to_s
    def meta_to_s(name=:to_s, priv=true)
      allow_private if priv
      __meta_to_s find_literal(name)
    end

    def last_match(mode, which)
      push_int Integer(mode)
      push_int Integer(which)
      invoke_primitive :regexp_last_match_result, 2
    end
  end

  class Generator
    module Literals
      def initialize_literals
        @literals_map = Hash.new { |h,k| h[k] = add_literal(k) }
        @literals = []
      end

      def find_literal(literal)
        @literals_map[literal]
      end

      def add_literal(literal)
        index = @literals.size
        @literals << literal
        index
      end

      def push_literal(literal)
        index = find_literal literal
        emit_push_literal index
        index
      end

      def push_unique_literal(literal)
        index = add_literal literal
        emit_push_literal index
        index
      end

      def push_literal_at(index)
        emit_push_literal index
        index
      end
    end

    module SendMethods
      def send(meth, count, priv=false)
        allow_private if priv

        unless count.kind_of? Fixnum
          raise CompileError, "count must be a number"
        end

        idx = find_literal(meth)

        # Don't use send_method, it's only for when the syntax
        # specified no arguments and no parens.
        send_stack idx, count
      end

      # Do a private send to self with no arguments specified, ie, a vcall
      # style send.
      def send_vcall(meth)
        idx = find_literal(meth)
        send_method idx
      end

      def send_with_block(meth, count, priv=false)
        allow_private if priv

        unless count.kind_of? Fixnum
          raise CompileError, "count must be a number"
        end

        idx = find_literal(meth)

        send_stack_with_block idx, count
      end

      def send_with_splat(meth, args, priv=false, concat=false)
        val = 0
        val |= InstructionSet::CALL_FLAG_CONCAT if concat
        set_call_flags val unless val == 0

        allow_private if priv

        idx = find_literal(meth)
        send_stack_with_splat idx, args
      end

      def send_super(meth, args, splat=false)
        idx = find_literal(meth)

        if splat
          send_super_stack_with_splat idx, args
        else
          send_super_stack_with_block idx, args
        end
      end
    end

    module Modifiers
      def break
        @instruction_list.break
      end

      def break=(label)
        @instruction_list.break = label
      end

      def redo
        @instruction_list.redo
      end

      def redo=(label)
        @instruction_list.redo = label
      end

      def next
        @instruction_list.next
      end

      def next=(label)
        @instruction_list.next = label
      end

      def retry
        @instruction_list.retry
      end

      def retry=(label)
        @instruction_list.retry = label
      end

      def push_modifiers
        @instruction_list.push_modifiers
      end

      def pop_modifiers
        @instruction_list.pop_modifiers
      end
    end

    module States
      def initialize_states
        @states = []
      end

      def state
        @states.last
      end

      def push_state(scope)
        @states << AST::State.new(scope)
      end

      def pop_state
        @states.pop
      end
    end

    module Lines
      def initialize_lines
        @last_line = nil
        @lines = []
      end

      def close
        if @lines.empty?
          msg = "closing a method definition with no line info: #{file}:#{line}"
          raise Exception, msg
        end

        @lines << ip
      end

      def set_line(line)
        raise Exception, "source code line cannot be nil" unless line

        if !@last_line
          @lines << ip
          @lines << line
          @last_line = line
        elsif line != @last_line
          if @lines[-2] == ip
            @lines[-1] = line
          else
            @lines << ip
            @lines << line
          end

          @last_line = line
        end
      end

      def definition_line(line)
        unless @instruction_list.empty?
          raise Exception, "only use #definition_line first"
        end

        @lines << -1
        @lines << line

        @last_line = line
      end
    end

    module InstructionListDelegator
      def new_label
        @instruction_list.new_label
      end

      def new_stack_local
        @instruction_list.new_stack_local
      end

      def ip
        @instruction_list.ip
      end
    end

    module DetectionHelper
      attr_accessor :detected_args, :detected_locals
      def initialize_detection
        @detected_args = 0
        @detected_locals = 0
      end

      def use_detected
        if @required_args < @detected_args
          @required_args = @detected_args
        end

        if @total_args < @detected_args
          @total_args = @detected_args
        end

        if @local_count < @detected_locals
          @local_count = @detected_locals
        end
      end

      def push_local(idx)
        if @detected_locals <= idx
          @detected_locals = idx + 1
        end

        super
      end

      def set_local(idx)
        if @detected_locals <= idx
          @detected_locals = idx + 1
        end

        super
      end
    end


    include GeneratorMethods
    include Literals
    include SendMethods
    include Modifiers
    include States
    include Lines
    include InstructionListDelegator
    include DetectionHelper
    attr_accessor :name, :file

    attr_accessor :local_count, :local_names
    attr_accessor :required_args, :post_args, :total_args, :splat_index
    attr_accessor :for_block

    def initialize
      @generators = []
      @instruction_list = InstructionList.new

      @required_args = 0
      @post_args = 0
      @total_args = 0

      @for_block = nil
      @primitive = nil

      initialize_literals
      initialize_states
      initialize_lines
      initialize_detection
    end

    def execute(node)
      node.bytecode self
    end
    alias_method :run, :execute

    def max_stack_size
      size = @instruction_list.max_stack_size + local_count
      size += 1 if @for_block
      size
    end

    def push_generator(generator)
      index = push_literal generator
      @generators << index
      index
    end

    def send_primitive(name)
      @primitive = name
    end

    def encode
      @instruction_list.optimize
      @instruction_list.materialize
      @instruction_list.validate_stack

      @iseq = @instruction_list.iseq

      @generators.each do |index|
        @literals[index].encode
      end
    end

    def package(klass)
      @generators.each do |index|
        @literals[index] = @literals[index].package klass
      end

      lines = @lines.collect do |line|
        if line.respond_to?(:materialize)
          line_ = nil
          catch(:last) do
            line_ = line.materialize
          end
          line_ || 1000
        else
          line
        end
      end

      #raise @iseq.inspect

      cm = klass.new
      cm.iseq           = @iseq
      cm.literals       = @literals.to_tuple
      cm.lines          = lines.to_tuple

      cm.required_args  = required_args
      cm.post_args      = post_args
      cm.total_args     = total_args
      cm.splat          = splat_index

      cm.local_count    = local_count
      cm.local_names    = local_names.to_tuple if local_names

      cm.stack_size     = max_stack_size

      cm.file           = file
      cm.name           = name

      cm.primitive      = @primitive
      if @for_block
        cm.add_metadata :for_block, true
      end

      cm
    end
  end
end
