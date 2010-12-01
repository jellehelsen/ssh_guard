require "spec_helper"

describe SshGuard::FirewallAdapters::IPFWAdapter do
  before(:each) do
    @firewall = SshGuard::FirewallAdapters::IPFWAdapter.new
  end
  it "should call ipfw" do
    @firewall.stub(:blocked?).and_return(false)
    @firewall.should_receive(:`).with("ipfw add 100 deny tcp from 192.168.1.1 to me ssh")
    @firewall.block_host('192.168.1.1')
  end
  it "should not block a host when it is already blocked" do
    msg = "Nov 24 21:15:53 mini sshd[55670]: reverse mapping checking getaddrinfo for client-200.106.67.47.speedy.net.pe [200.106.67.47] failed - POSSIBLE BREAK-IN ATTEMPT!"
    @firewall.should_not_receive(:`).with("ipfw add deny tcp from 192.168.1.1 to me ssh")
    @firewall.should_receive(:blocked?).and_return(true)
    @firewall.block_host('192.168.1.1')
  end
  
end
