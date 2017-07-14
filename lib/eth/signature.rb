module Eth
  class Signature

    attr_accessor :message, :signer, :prefixed_message, :hash, :hash_hex, :signature, :signature_hex, :rpc, :rpc_hex, :v, :r, :s

    def initialize(message)
      @message = message
    end

  end
end
