require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe SshGuard do
  before(:each) do 
    @guard = SshGuard::Core.new
  end

  it "parses an input line" do
    lambda { @guard << "input" }.should_not raise_error
  end

  it "should connect to an in-memory database" do
    Sequel.should_receive(:sqlite).and_return(m=mock())
    m.should_receive(:create_table)
    @guard = SshGuard::Core.new
  end

  it "should add an entry for possible break-in attempt" do
    msg = "Nov 24 21:15:53 mini sshd[55670]: reverse mapping checking getaddrinfo for client-200.106.67.47.speedy.net.pe [200.106.67.47] failed - POSSIBLE BREAK-IN ATTEMPT!"
    @guard.database.should_receive(:add_entry).with({:timestamp => Time.parse("Nov 24 21:15:53"), :ip_address => "200.106.67.47"})
    @guard << msg
  end

  it "should ignore other input" do
    @guard.database.should_not_receive(:add_entry)
    @guard << "other input"
  end
  
  it "should block the host if failed more than 5 times" do
    @guard.database.db.stub_chain(:[], :where, :count).and_return(6)
    @guard.database.should_block?("192.168.1.2").should be_true
  end

  it "should tell the firewall about host to block" do
    @guard.database.stub(:should_block?).and_return(true)
    @guard.stub(:firewall).and_return(m=mock())
    m.should_receive(:block_host)
    msg = "Nov 24 21:15:53 mini sshd[55670]: reverse mapping checking getaddrinfo for client-200.106.67.47.speedy.net.pe [200.106.67.47] failed - POSSIBLE BREAK-IN ATTEMPT!"
    @guard << msg
  end
  
  it "should call ipfw" do
    @guard.firewall.should_receive(:`)
    @guard.database.stub(:should_block?).and_return(true)
    msg = "Nov 24 21:15:53 mini sshd[55670]: reverse mapping checking getaddrinfo for client-200.106.67.47.speedy.net.pe [200.106.67.47] failed - POSSIBLE BREAK-IN ATTEMPT!"
    @guard << msg
  end
end
