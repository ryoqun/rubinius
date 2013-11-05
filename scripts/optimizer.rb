require "./scripts/inject"

    ##
    # Represents virtual machine's CPU instruction.
    # Instructions are organized into instruction
    # sequences known as iSeq, forming body
    # of CompiledCodes.
    #
    # To generate VM opcodes documentation
    # use rake doc:vm task.
    class Rubinius::CompiledCode::Instruction
      class Association
        def initialize(index)
          @index = index
        end

        def inspect
          "literals[#{@index}]"
        end
      end

      class Location
        FORMAT = "%04d:"

        def initialize(location)
          @location = location
        end

        def inspect
          FORMAT % @location
        end
      end

      def initialize(inst, code, ip)
        @instruction = inst[0]
        @args = inst[1..-1]
        @comment = nil

        @args.each_index do |i|
          case @instruction.args[i]
          when :literal
            @args[i] = code.literals[@args[i]]
          when :local
            # TODO: Blocks should be able to retrieve local names as well,
            # but need access to method corresponding to home context
            if code.local_names and !code.is_block?
              @comment = code.local_names[args[i]].to_s
            end
          when :association
            @args[i] = Association.new(args[i])
          when :location
            @args[i] = Location.new(args[i])
          end
        end

        @compiled_code = code
        @ip = ip
      end

      # Instruction pointer
      attr_reader :ip

      ##
      # Return the line that this instruction is on in the method
      #
      def line
        @compiled_code.line_from_ip(ip)
      end

      ##
      # Returns the OpCode object
      #
      attr_reader :instruction

      ##
      # Returns the symbol representing the opcode for this instruction.
      #
      def opcode
        @instruction.opcode
      end

      ##
      # Returns an array of 0 to 2 arguments, depending on the opcode.
      #
      attr_reader :args

      ##
      # Returns a Fixnum indicating how wide the instruction takes up
      # in the instruction stream
      #
      def size
        @args.size + 1
      end

      ##
      # A nice human readable interpretation of this set of instructions
      def to_s
        str = "#{Location::FORMAT}  %-27s" % [@ip, opcode]
        str << @args.map{ |a| a.inspect }.join(', ')
        if @comment
          str << "    # #{@comment}"
        end

        return str
      end
    end

class Tuple < Array
  alias_method :to_tuple, :to_a
end

module Rubinius::ToolSet.current::TS
  class Rubinius::CompiledCode
    ##
    # Return the line of source code at +ip+.
    #
    # @param  [Fixnum] ip
    # @return [Fixnum] line
    def line_from_ip(ip)
      return -1 unless @lines
      return 0 if @lines.size < 2

      low = 0
      high = @lines.size / 2 - 1

      while low <= high
        # the chance that we're going from a fixnum to a bignum
        # here is low, but we still try to prevent that.
        mid = low + ((high - low) / 2)

        line_index = mid * 2 + 1

        if ip < @lines.at(line_index - 1)
          high = mid - 1
        elsif ip >= @lines.at(line_index + 1)
          low = mid + 1
        else
          return @lines.at(line_index)
        end
      end

      @lines.at(@lines.size - 2)
    end
    def decode(bytecodes = @iseq)
      decoder = Rubinius::InstructionDecoder.new(bytecodes)
      stream = decoder.decode(false)
      ip = 0

      stream.map do |inst|
        instruct = Rubinius::CompiledCode::Instruction.new(inst, self, ip)
        ip += instruct.size
        instruct
      end
    end

    def get_metadata(key)
      return nil unless instance_variable_defined?(:@metadata) and @metadata.kind_of? Tuple

      i = 0
      while i < @metadata.size
        if @metadata[i] == key
          return @metadata[i + 1]
        end

        i += 2
      end

      return nil
    end

    ##
    # Is this actually a block of code?
    #
    # @return [Boolean]
    def is_block?
      get_metadata(:for_block)
    end

    def for_eval?
      get_metadata(:for_eval)
    end

    def for_module_body?
      get_metadata(:for_module_body)
    end
  end

  class Rubinius::OptimizedCode < Rubinius::CompiledCode
    attr_accessor :original_code
  end

  class Generator
    alias_method :__package__, :package
    def package(klass)
      compiled_code = __package__(klass)

      print "#{compiled_code.name} #{compiled_code.decode.size}"
      opt = Rubinius::Optimizer.new(compiled_code)
      opt.add_pass(Rubinius::Optimizer::FlowAnalysis)
      basename = "#{compiled_code.file.to_s.gsub('/', '_')}:#{compiled_code.line_from_ip(0)}_#{compiled_code.name}"
      opt.add_pass(Rubinius::Optimizer::FlowPrinter, basename)
      opt.add_pass(Rubinius::Optimizer::DataFlowAnalyzer)
      opt.add_pass(Rubinius::Optimizer::DataFlowPrinter, basename)
      opt.add_pass(Rubinius::Optimizer::StackAnalyzer)
      opt.add_pass(Rubinius::Optimizer::StackPrinter, basename)
      opt.add_pass(Rubinius::Optimizer::PruneUnused)
      opted = opt.run
      puts "=> #{opted.decode.size}"
      opt = Rubinius::Optimizer.new(compiled_code)

      optimized_code = compiled_code
      optimized_code
    end
  end
end
