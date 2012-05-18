# -*- encoding: us-ascii -*-

module Rubinius
  class Generator
    include GeneratorMethods

    ##
    # Jump label for the branch instructions. The use scenarios for labels:
    #   1. Used and then set
    #        g.gif label
    #        ...
    #        label.set!
    #   2. Set and then used
    #        label.set!
    #        ...
    #        g.git label
    #   3. 1, 2
    #
    # Many labels are only used once. This class employs two small
    # optimizations. First, for the case where a label is used once then set,
    # the label merely records the point it was used and updates that location
    # to the concrete IP when the label is set. In the case where the label is
    # used multiple times, it records each location and updates them to an IP
    # when the label is set. In both cases, once the label is set, each use
    # after that updates the instruction stream with a concrete IP at the
    # point the label is used. This avoids the need to ever record all the
    # labels or search through the stream later to change symbolic labels into
    # concrete IP's.

    class Label
      attr_reader :used, :basic_block
      alias_method :used?, :used

      def initialize(generator)
        @generator   = generator
        @basic_block = generator.new_basic_block
        @position    = nil
        @used        = false
        @location    = nil
        @locations   = nil
      end

      def set!
        @position = @generator.ip
        @position.basic_blocks << @basic_block

        if @locations
          @locations.each { |x| set_jump_slot(x) }
        elsif @location
          set_jump_slot(@location)
        end
      end

      def used_at(ip)
        if @position
          set_jump_slot(ip)
        elsif !@location
          @location = ip
        elsif @locations
          @locations << ip
        else
          @locations = [@location, ip]
        end
        @used = true
      end

      private
      def set_jump_slot(ip)
        @position.jump_from(ip)
        ip[:slot] = @position
      end
    end

    class BasicBlock
      attr_accessor :left
      attr_accessor :right

      def initialize(generator)
        @generator  = generator
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
        line = nil #@generator.ip_to_line(ip)
        "#name: line: #{line}, IP: #{ip}"
      end

      SEPARATOR_SIZE = 40

      def invalid(message)
        if $DEBUG
          puts message
          name = @generator.name.inspect
          size = (SEPARATOR_SIZE - name.size - 2) / 2
          size = 1 if size <= 0
          puts "\n#{"=" * size} #{name} #{"=" * (size + name.size % 2)}"

          literals = @generator.literals
          names = @generator.local_names
          stream = @generator.stream
          i = 0
          n = stream.size
          stack = 0

          while i < n
            insn = InstructionSet[stream[i]]
            printf "[%3d] %04d  %-28s" % [stack, i, insn.opcode.inspect]

            args = stream[i+1, insn.size-1]
            if insn.size > 1
              insn.args.each_with_index do |kind, index|
                arg = args[index]
                case kind
                when :literal
                  printf "%s " % literals[arg].inspect
                when :local
                  printf "%s " % (names ? names[arg] : arg)
                else
                  printf "%d " % arg
                end
              end
            end

            puts

            if insn.variable_stack?
              use = insn.stack_consumed
              if use.kind_of? Array
                use = args[use[1] - 1] + use[0]
              end

              pro = insn.stack_produced
              if pro.kind_of? Array
                pro = (args[pro[1] - 1] * pro[2]) + pro[0]
              end

              stack += pro - use
            else
              stack += insn.stack_difference
            end

            i += insn.size
          end

          puts "-" * SEPARATOR_SIZE
        end

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
      @instruction_list = InstructionList.new
      @literals_map = Hash.new { |h,k| h[k] = add_literal(k) }
      @literals = []
      @primitive = nil
      @for_block = nil

      @required_args = 0
      @post_args = 0
      @total_args = 0

      @detected_args = 0
      @detected_locals = 0

      @states = []
      @generators = []

      @current_line = nil
      @definition_line = nil
    end

    attr_accessor :file, :name,
                  :required_args, :post_args, :total_args, :splat_index,
                  :local_count, :local_names, :primitive, :for_block,
                  :detected_args, :detected_locals

    def execute(node)
      node.bytecode self
    end

    alias_method :run, :execute

    # Formalizers

    def encode
      @instruction_list.optimize
      @instruction_list.source
      @instruction_list.materialize
      @instruction_list.validate_stack
      @iseq = @instruction_list.iseq

      if @definition_line
        @lines = [-1, @definition_line] + @instruction_list.lines
      else
        @lines = @instruction_list.lines
      end

      @generators.each { |x| @literals[x].encode }
    end

    def package(klass)
      @generators.each { |x| @literals[x] = @literals[x].package klass }

      cm = klass.new
      cm.iseq           = @iseq
      cm.literals       = @literals.to_tuple
      cm.lines          = @lines.to_tuple

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
      cm.verify_bytecode if cm.respond_to?(:verify_bytecode)

      cm
    end

    alias_method :dup,  :dup_top
    alias_method :git,  :goto_if_true
    alias_method :gif,  :goto_if_false
    alias_method :swap, :swap_stack

    def create_instruction(name)
      @instruction = @instruction_list.create_instruction(name, @current_line)
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

    module Literals
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
      def close
        if @current_line.nil?
          msg = "closing a method definition with no line info: #{file}:#{line}"
          raise Exception, msg
        end
      end

      def set_line(line)
        raise Exception, "source code line cannot be nil" unless line
        @current_line = line
      end

      def definition_line(line)
        unless @instruction_list.empty?
          raise Exception, "only use #definition_line first"
        end

        @definition_line = line
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


    include Literals
    include SendMethods
    include Modifiers
    include States
    include Lines
    include InstructionListDelegator
    include DetectionHelper

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
  end

  class Slot
    attr_accessor :instruction, :basic_blocks, :jumps, :line

    def initialize
      @instruction = nil
      @basic_blocks = []
      @jumps = []
    end

    def jump_from(instruction)
      @jumps << instruction
    end

    def materialize
      @instruction[:ip]
    end
  end

  class InstructionList
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

    def used_slots
      @instruction_slots[0..-2]
    end

    def instructions
      used_slots.collect(&:instruction)
    end

    def empty?
      used_slots.empty?
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

    def last_slot
      @instruction_slots.last
    end

    def create_instruction(name, current_line)
      instruction = {:name => name}
      last_slot.instruction = instruction
      last_slot.line = current_line
      @instruction_slots << Slot.new
      instruction
    end

    def ip
      last_slot
    end

    def optimize
      last_slot = nil

      used_slots.each_with_index do |slot, index|
        instruction = slot.instruction

        last_instruction = last_slot.instruction if last_slot

        if last_instruction and ENV["NO_OPT"].nil?
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

          if [:goto].include?(instruction[:name]) and
             [:push_nil].include?(last_instruction[:name]) and
             instruction[:slot].instruction[:name] == :pop and
             last_slot.basic_blocks.empty? and
             slot.basic_blocks.empty? and
             instruction[:slot].basic_blocks.size == 1 and
             last_slot.jumps.empty? and
             slot.jumps.empty? and
             instruction[:slot].jumps.size == 1 and
             [:ret, :raise_return, :ensure_return, :raise_exc, :reraise, :break].include?( @instruction_slots[@instruction_slots.index(instruction[:slot]) - 1].instruction[:name])
            #puts @instruction_slots[@instruction_slots.index(instruction[:slot]) - 1].instruction[:name]
            #puts "push_nil_goto?"
            #puts last_slot.jumps.size
            #puts slot.jumps.size
            #puts instruction[:slot].jumps.size
            #puts "bb"
            #puts last_slot.basic_blocks.size
            #puts slot.basic_blocks.size
            #puts instruction[:slot].basic_blocks.size

            #previous_slot = @instruction_slots[index - 1]
            #p @instruction_slots.collect(&:basic_blocks).collect(&:size)

            #previous_slot.basic_blocks = previous_slot.basic_blocks + last_slot.basic_blocks
            #last_slot.basic_blocks.clear
            #previous_goto_slot = @instruction_slots[@instruction_slots.index(instruction[:slot]) - 1]
            #p previous_goto_slot.instruction[:name]
            next_goto_slot = @instruction_slots[@instruction_slots.index(instruction[:slot]) + 1]
            next_goto_slot.basic_blocks = instruction[:slot].basic_blocks + next_goto_slot.basic_blocks
            instruction[:slot].basic_blocks.clear
            jump_slot = instruction[:slot]

            last_instruction[:remove] = true
            instruction[:slot].instruction[:remove] = true
            instruction[:slot] = next_goto_slot
            next_goto_slot.jumps = jump_slot.jumps + next_goto_slot.jumps
            jump_slot.jumps.clear
          elsif [:goto].include?(instruction[:name]) and
             [:push_nil].include?(last_instruction[:name]) and
             instruction[:slot].instruction[:name] == :pop and
             instruction[:slot].jumps.size == 1 and
             [:ret, :raise_return, :ensure_return, :raise_exc, :reraise, :break].include?( @instruction_slots[@instruction_slots.index(instruction[:slot]) - 1].instruction[:name])
            puts "aaaaa" + @instruction_slots[@instruction_slots.index(instruction[:slot]) - 1].instruction[:name].to_s
          end

          if [:pop].include?(instruction[:name]) and
             [:yield_stack].include?(last_instruction[:name]) and
             slot.jumps.empty?
            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = :meta_yield_stack_pop
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:meta_yield_stack_pop]
            last_instruction[:stack][1] = 0
            instruction[:remove] = true
          end

          if [:pop].include?(instruction[:name]) and
             [:send_stack_with_splat, :send_stack_with_block].include?(last_instruction[:name]) and
             slot.jumps.empty?
            name = "meta_#{last_instruction[:name]}_pop".to_sym
            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = name
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[name]
            last_instruction[:stack][1] = 0
            instruction[:remove] = true
          end

          if [:pop].include?(instruction[:name]) and
             [:set_ivar].include?(last_instruction[:name]) and
             slot.jumps.empty?
            #puts "set_ivar"
            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = :meta_set_ivar_pop
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:meta_set_ivar_pop]
            last_instruction[:stack][1] = 0
            instruction[:remove] = true
          end

          if [:pop].include?(instruction[:name]) and
             [:set_stack_local].include?(last_instruction[:name]) and
             slot.jumps.empty?
            #puts "set_stack_local"
            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = :meta_set_stack_local_pop
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:meta_set_stack_local_pop]
            last_instruction[:stack][1] = 0
            instruction[:remove] = true
          end

          if [:pop].include?(instruction[:name]) and
             [:set_local].include?(last_instruction[:name]) and
             slot.jumps.empty?
            #puts "set_local"
            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = :meta_set_local_pop
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:meta_set_local_pop]
            last_instruction[:stack][1] = 0
            instruction[:remove] = true
          end

          if ENV["SEND_METHOD"] and [:send_stack].include?(instruction[:name]) and instruction[:stream].last.zero?
            instruction[:name] = :send_method
            instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:send_method]
            instruction[:stream].pop
          end

          if [:pop].include?(instruction[:name]) and
             [:send_stack].include?(last_instruction[:name]) and
             slot.jumps.empty?
            #puts "meta_send_stack"

            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = :meta_send_stack_pop
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:meta_send_stack_pop]
            last_instruction[:stack][1] = 0
            instruction[:remove] = true
          end

          if [:pop].include?(instruction[:name]) and
             [:set_local_depth].include?(last_instruction[:name]) and
             slot.jumps.empty?
            #puts "meta_set_local_depth_pop"

            last_slot.basic_blocks = last_slot.basic_blocks + slot.basic_blocks
            slot.basic_blocks.clear

            last_instruction[:name] = :meta_set_local_depth_pop
            last_instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[:meta_set_local_depth_pop]
            last_instruction[:stack] = [1, 0]
            instruction[:remove] = true
          end

          if [:goto_if_true].include?(instruction[:name]) and
             [:push_false].include?(last_instruction[:name]) and
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

          if [:goto_if_false].include?(instruction[:name]) and
             [:push_true].include?(last_instruction[:name]) and
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

          if instruction[:name] == :pop and
             [:push_nil, :push_true, :push_false].include?(last_instruction[:name]) and
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
        slot.instruction and slot.instruction[:name] and slot.instruction[:remove]
      end

      used_slots.each_with_index do |slot, index|
        instruction = slot.instruction

        if instruction[:name] == :set_local
          index = instruction[:stream].last
          if index <= 2
            meta = :"meta_set_local_#{index}"
            instruction[:name] = meta
            instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[meta]
            instruction[:stream].pop
          end
        end

        if instruction[:name] == :send_stack
          count = instruction[:stream].last
          if count <= 2
            meta = :"meta_send_stack_#{count}"
            instruction[:name] = meta
            instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[meta]
            instruction[:stream].pop
          end
        end

        if instruction[:name] == :meta_send_stack_pop
          count = instruction[:stream].last
          if count <= 2
            meta = :"meta_send_stack_#{count}_pop"
            instruction[:name] = meta
            instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[meta]
            instruction[:stream].pop
          end
        end

        if instruction[:name] == :meta_set_local_pop
          index = instruction[:stream].last
          if index <= 2
            meta = :"meta_set_local_#{index}_pop"
            instruction[:name] = meta
            instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[meta]
            instruction[:stream].pop
          end
        end

        if instruction[:name] == :push_local
          index = instruction[:stream].last
          if index <= 2
            meta = :"meta_push_local_#{index}"
            instruction[:name] = meta
            instruction[:stream][0] = Rubinius::InstructionSet.opcodes_map[meta]
            instruction[:stream].pop
          end
        end
      end
    end

    def source
      last_line = nil
      @instruction_slots.each do |slot|
        if slot.line
          if last_line != slot.line
            slot.instruction[:new_line] = true
          end
          last_line = slot.line
        end
      end

      slots = []
      @instruction_slots.each do |slot|
        if slot.instruction and slot.instruction[:new_line] and slot.line > 0
          new_slot = Slot.new
          new_slot.instruction = slot.instruction
          new_slot.line = slot.line

          instruction = {:stream => [1, slot.line - 1], :name => :source, :stack => [0, 0]}
          slot.instruction = instruction

          slots << slot
          slots << new_slot
        else
          slots << slot
        end
      end
      @instruction_slots = slots
    end

    def materialize
      @instruction_slots.freeze

      calculate_ip
      @instruction_slots.each(&:freeze)

      materialize_position
    end

    def calculate_ip
      ip = 0
      instructions.each do |instruction|
        instruction[:ip] = ip
        ip += instruction[:stream].size
      end
      last_slot.instruction = {:ip => ip}
    end

    def replace_with_ip(instruction)
      basic_block = instruction[:stream][1]
      instruction[:stream][1] = instruction[:slot].materialize
      basic_block
    end

    def materialize_position
      @enter_block = current = new_basic_block

      used_slots.each do |slot|
        instruction = slot.instruction

        slot.basic_blocks.each do |basic_block|
          current.left = basic_block
          current.close
          current = basic_block
        end

        if instruction[:name] != :cast_array
          current.add_stack(*instruction[:stack])
        end

        case instruction[:name]
        when :goto
          basic_block = replace_with_ip(instruction)

          current.left = basic_block
          current.close
          current = new_basic_block
        when :goto_if_false, :goto_if_true, :setup_unwind
          basic_block = replace_with_ip(instruction)

          current.left = basic_block
          current.close
          current = current.right = new_basic_block
        when :ret, :raise_return, :ensure_return
          current.close_and_exit instruction
          current = new_basic_block
        when :raise_exc, :reraise, :break
          current.close
          current = new_basic_block
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
        raise e
      end
    end

    def iseq
      InstructionSequence.new(instruction_stream.to_tuple)
    end

    def lines
      lines = []
      last_line = nil

      used_slots.each.with_index do |slot, index|
        if lines.empty?
          if slot.line
            lines << 0
            lines << slot.line
            last_line = slot.line
          end
        else
          if slot.line != last_line
            if lines[-2] == @instruction_slots[index].instruction[:ip]
              lines[-1] = slot.line
            else
              lines << @instruction_slots[index].instruction[:ip]
              lines << slot.line
            end
            last_line = slot.line
          end
        end
      end
      lines << last_slot.instruction[:ip]
      lines
    end

    def new_basic_block
      Generator::BasicBlock.new(self)
    end

    def new_label
      Generator::Label.new(self)
    end

    private
    def instruction_stream
      stream = []
      instructions.each do |instruction|
        stream += instruction[:stream]
      end
      stream
    end
  end

end
