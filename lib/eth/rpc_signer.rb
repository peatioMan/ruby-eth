module Eth
  class RpcSigner

    attr_accessor :key

    def initialize(key)
      @key = key
    end

    def sign_message(message)
      payload = Eth::Signature.new(message)
      payload.signer = @key.address
      payload.padded_message = Eth::Utils.prefix_message(message)
      payload.hash = Eth::Utils.keccak256(payload.padded_message)
      payload.signature = @key.sign_hash(payload.hash)
      payload.v, payload.r, payload.s = Eth::Utils.v_r_s_for(payload.signature)
      payload.rpc_signature = Eth::Utils.zpad_int(payload.r, 32) + Eth::Utils.zpad_int(payload.s, 32) + [(payload.v - 27)].pack('C')
      return payload
    end

  end


end
