require File.expand_path('../../../spec_helper', __FILE__)
require File.expand_path('../fixtures/classes', __FILE__)

describe "Thread#[]=" do
  ruby_version_is ""..."1.9" do
    it "raises exceptions on the wrong type of keys" do
      lambda { Thread.current[nil] = true }.should raise_error(TypeError)
      lambda { Thread.current[5] = true }.should raise_error(ArgumentError)
    end
  end

  ruby_version_is "1.9" do
    it "raises exceptions on the wrong type of keys" do
      lambda { Thread.current[nil] = true }.should raise_error(TypeError)
      lambda { Thread.current[5] = true }.should raise_error(TypeError)
    end

    it "is not shared across fibers" do
      fib = Fiber.new do
        Thread.current[:value] = 1
        Fiber.yield
        Thread.current[:value].should == 1
      end
      fib.resume
      Thread.current[:value].should be_nil
      Thread.current[:value] = 2
      fib.resume
      Thread.current[:value] = 2
    end

  end
end
