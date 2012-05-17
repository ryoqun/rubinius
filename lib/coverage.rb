module Coverage
  class << self
    def start(*args)
    end

    def result
      Hash[Thread.current.coverage.to_a.collect{|f,c| [f.to_s, c]}]
    end
  end
end
