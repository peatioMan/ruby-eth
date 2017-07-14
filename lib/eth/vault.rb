module Eth
  class Vault

    attr_accessor :hd_path_string, :master, :mnemonic

    class << self

      def pad_mnemonic(mnemonic)
        mnemonic.rjust(180, ' ')
      end

      def unpad_mnemonic(mnemonic)
        mnemonic.strip!
      end
    end

    def initialize(opts = {secret_seed_phrase: nil, hd_path_string: "m/0'/0'/0'"})
      if opts[:secret_seed_phrase]
        secret_seed_phrase = self.class.pad_mnemonic(opts[:secret_seed_phrase])
        seed_hex = Bitcoin::Trezor::Mnemonic.to_seed(secret_seed_phrase)
      else
        secret_seed_phrase = self.class.pad_mnemonic(Bitcoin::Trezor::Mnemonic.to_mnemonic(RbNaCl::Random.random_bytes(32)))
        seed_hex = Bitcoin::Trezor::Mnemonic.to_seed(secret_seed_phrase)
      end
      @mnemonic = self.class.unpad_mnemonic(opts[:secret_seed_phrase])
      @hd_path_string = opts[:hd_path_string]
      @master = MoneyTree::Master.new(seed_hex: seed_hex)
    end

    def get_node(index = 0)
      if index == 0
        hd_path = @hd_path_string
      else
        hd_path = "#{@hd_path_string}/#{index}'"
      end
      @master.node_from_path(hd_path)
    end

    def get_key(index = 0)
      Eth::Key.from_node(get_node(index))
    end

  end
end
