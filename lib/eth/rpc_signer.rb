module Eth
  class RpcSigner

    attr_accessor :key

    def initialize(key)
      @key = key
    end

    def sign_message(message)
      payload = Eth::Signature.new(message)
      payload.prefixed_message = Eth::Utils.prefix_message(message)
      payload.hash = Eth::Utils.keccak256(payload.prefixed_message)
      payload.hash_hex = Eth::Utils.bin_to_prefixed_hex(payload.hash)
      payload.signature = @key.sign(payload.prefixed_message)
      payload.signature_hex = Eth::Utils.bin_to_prefixed_hex(payload.signature)
      payload.v, payload.r, payload.s = Eth::Utils.v_r_s_for(payload.signature)
      payload.rpc = Eth::Utils.zpad_int(payload.r, 32) + Eth::Utils.zpad_int(payload.s, 32) + [(payload.v - 27)].pack('C')
      payload.rpc_hex = Eth::Utils.bin_to_prefixed_hex(payload.rpc)
      return payload
    end

  end


end
