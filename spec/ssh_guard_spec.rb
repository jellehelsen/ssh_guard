require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe SshGuard::Core do
  before(:each) do 
    SshGuard::Core.stub(:i_am_root?).and_return(:true)
    @guard = SshGuard::Core.new
    @guard.firewall.stub(:blocked?)
  end

  it "parses an input line" do
    lambda { @guard << "input" }.should_not raise_error
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
  
  it "should tell the firewall about host to block" do
    @guard.database.stub(:should_block?).and_return(true)
    @guard.stub(:firewall).and_return(m=mock())
    m.stub(:blocked?).and_return(false)
    m.should_receive(:block_host)
    msg = "Nov 24 21:15:53 mini sshd[55670]: reverse mapping checking getaddrinfo for client-200.106.67.47.speedy.net.pe [200.106.67.47] failed - POSSIBLE BREAK-IN ATTEMPT!"
    @guard << msg
  end
  
  describe "log messages" do
    it "should add entry for failed authentication" do
      msg = "Nov 24 21:15:55 mini sshd[55670]: error: PAM: authentication error for root from 200.106.67.47 via 192.168.1.2"
      @guard.database.should_receive(:add_entry).with({:timestamp => Time.parse("Nov 24 21:15:55"), :ip_address => "200.106.67.47"})
      @guard << msg
    end
    
    it "should add entry for invalid user" do
      msg = "Nov 24 17:03:55 mini sshd[47367]: Invalid user staff from 221.13.5.92"
      @guard.database.should_receive(:add_entry).with({:timestamp => Time.parse("Nov 24 17:03:55"), :ip_address => "221.13.5.92"})
      @guard << msg
    end
    
    it "should add entry for no identification string" do
      msg = "Nov 24 20:33:23 mini sshd[54157]: Did not receive identification string from 85.172.214.7"
      @guard.database.should_receive(:add_entry).with({:timestamp => Time.parse("Nov 24 20:33:23"), :ip_address => "85.172.214.7"})
      @guard << msg
    end
  end
  
  describe "on osx" do
    it "should tail /var/log/secure.log" do
      IO.should_receive(:popen).with("tail -f /var/log/secure.log")
      @guard.start
    end
  end
end
