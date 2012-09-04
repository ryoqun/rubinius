describe :net_ftp_request_get, :shared => true do
  before(:all) do
    NetHTTPSpecs.start_server
  end

  after(:all) do
    NetHTTPSpecs.stop_server
  end

  before(:each) do
    @http = Net::HTTP.start("localhost", 3333)
  end

  after(:each) do
    @http.finish if @http.started?
  end

  describe "when passed no block" do
  end

  describe "when passed a block" do
  end
end
