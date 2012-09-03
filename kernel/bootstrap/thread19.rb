# -*- encoding: us-ascii -*-

class Thread
  def self.start(*args)
    raise ArgumentError.new("no block passed to Thread.start") unless block_given?

    thr = Rubinius.invoke_primitive :thread_allocate, self

    Rubinius.asm(args, thr) do |args, obj|
      run obj
      dup

      push_false
      send :setup, 1, true
      pop

      run args
      push_block
      send_with_splat :__thread_initialize__, 0, true
      # no pop here, as .asm blocks imply a pop as they're not
      # allowed to leak a stack value
    end

    return thr
  end

  class << self
    alias_method :fork, :start
  end

  def self.stop
    sleep
    nil
  end

  # Called by Thread#fork in the new thread
  #
  def __run__()
    begin
      begin
        @lock.send nil
        @result = @block.call(*@args)
      ensure
        #puts "before_join_channel"
        begin
          @lock.receive
          #puts "before_join_channel after lock receive!!"
          Rubinius.check_interrupts
          #Proc.new{}.call
          #p Rubinius.thread_state[0]
        ensure
          #p Rubinius.thread_state
          unlock_locks
          #puts "really before join channel"
          #p @joins
          @joins.each { |join| join.send self }
          #p @joins
          #puts "after_join_channel"
        end
      end
    rescue Die
      #@killed = true
      @exception = nil
    rescue Exception => e
      # I don't really get this, but this is MRI's behavior. If we're dying
      # by request, ignore any raised exception.
      @exception = e # unless @dying
    ensure
      @alive = false
      @lock.send nil
    end

    if @exception
      if abort_on_exception or Thread.abort_on_exception
        Thread.main.raise @exception
      elsif $DEBUG
        STDERR.puts "Exception in thread: #{@exception.message} (#{@exception.class})"
      end
    end
  end

  def setup(prime_lock)
    @group = nil
    @alive = true
    @result = false
    @exception = nil
    @critical = false
    @dying = false
    @lock = Rubinius::Channel.new
    @lock.send nil if prime_lock
    @joins = []
    @killed = false
  end

  def value
    join_inner do
      @killed ? nil : @result
    end
  end
end
