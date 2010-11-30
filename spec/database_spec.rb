require "spec_helper"

describe SshGuard::Database do
  it "should connect to an in-memory database" do
    Sequel.should_receive(:sqlite).and_return(m=mock())
    m.should_receive(:create_table)
    @db = SshGuard::Database.new
  end
  
  it "should block the host if failed more than 10 times" do
    @db = SshGuard::Database.new
    @db.db.stub_chain(:[], :where, :count).and_return(11)
    @db.should_block?("192.168.1.2").should be_true
  end
  it "should not block the host if failed less than 10 times" do
    @db = SshGuard::Database.new
    @db.db.stub_chain(:[], :where, :count).and_return(9)
    @db.should_block?("192.168.1.2").should be_false
  end  
end