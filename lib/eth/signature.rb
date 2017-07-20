class String

  def to_urlsafe_base64
    if is_hex?
      Base64.urlsafe_encode64(Eth::Utils.hex_to_bin(self))
    else
      Base64.urlsafe_encode64(self)
    end
  end

  def from_urlsafe_base64
    Base64.urlsafe_decode64(self)
  end

  def to_hex
    if self.is_hex?
      return self
    else
      Eth::Utils.bin_to_prefixed_hex(self)
    end
  end

  def is_hex?
    !self.gsub("0x", '')[/\H/]
  end

end

module Eth
  class Signature

    attr_accessor :message, 
                  :signer, 
                  :padded_message,
                  :hash, 
                  :signature, 
                  :rpc_signature, 
                  :v, 
                  :r, 
                  :s

    def initialize(message)
      @message = message
    end

  end
end
