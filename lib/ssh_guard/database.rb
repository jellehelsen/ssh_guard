require "sequel"
module SshGuard
  class Database
    attr_reader :db

    def initialize()
      @db = Sequel.sqlite
      @db.create_table :entries do 
        primary_key :id
        String :ip_address
        Time :timestamp
      end
    end
  
    def add_entry(entry={})
      db[:entries].insert(entry) unless entry.empty?
    end

    def should_block?(ip_address)
      count = @db[:entries].where({:ip_address => ip_address}).count 
      count > 5
    end
  end  
end
