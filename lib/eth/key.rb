module Eth
  class Key
    autoload :Decrypter, 'eth/key/decrypter'
    autoload :Encrypter, 'eth/key/encrypter'

    attr_accessor :private_key, :public_key

    def self.encrypt(key, password)
      key = new(priv: key) unless key.is_a?(Key)

      Encrypter.perform key.private_hex, password
    end

    def self.decrypt(data, password)
      priv = Decrypter.perform data, password
      default priv: priv
    end

    class << self
      def from_private_key_hex(private_key_hex)
        private_key = MoneyTree::PrivateKey.new(key: private_key_hex)
        private_key.remove_instance_variable(:@raw_key)
        private_key.options[:key] = nil
        key = self.new
        key.private_key = private_key
        key.public_key = MoneyTree::PublicKey.new private_key, compressed: false
        return key
      end

      def from_node(node)
        key = self.new
        private_key = MoneyTree::PrivateKey.new(key: node.private_key.to_hex)
        public_key = MoneyTree::PublicKey.new(node.private_key, compressed: false)
        key.private_key = private_key
        key.public_key = public_key
        return key
      end

      def default(priv: nil)
        key = self.new
        private_key = MoneyTree::PrivateKey.new key: priv
        public_key = MoneyTree::PublicKey.new(private_key, compressed: false)
        key.private_key = private_key
        key.public_key = public_key
        return key
      end

    end

    #def initialize(priv: nil)
      #@private_key = MoneyTree::PrivateKey.new key: priv
      #@public_key = MoneyTree::PublicKey.new private_key, compressed: false
    #end

    def private_hex
      private_key.to_hex
    end

    def public_bytes
      public_key.to_bytes
    end

    def public_hex
      public_key.to_hex
    end

    def address
      Utils.public_key_to_address public_hex
    end
    alias_method :to_address, :address

    def sign(message)
      sign_hash message_hash(message)
    end

    def sign_hash(hash)
      loop do
        signature = OpenSsl.sign_compact hash, private_hex, public_hex
        return signature if valid_s? signature
      end
    end

    def verify_signature(message, signature)
      hash = message_hash(message)
      public_hex == OpenSsl.recover_compact(hash, signature)
    end

    def get_signer_key(message, signature)
      hash = message_hash(message)
      signer_public_hex = OpenSsl.recover_compact(hash, signature)
      signer_public_key = MoneyTree::PublicKey.new(signer_public_hex, compressed: false)
      signer_key = Eth::Key.new
      signer_key.public_key = signer_public_key
      return signer_key
    end

    def verify_rpc_signature(message, signature, signer_address)
      signer = get_signer_key(message, signature)
      signer.address == signer_address 
    end

    def verify_rpc_signature_no_prefix(message, signature, signer_address)
      prefixed_message = Eth::Utils.prefix_message(message)
      verify_rpc_signature(prefixed_message, signature, signer_address) 
    end

    private

    def message_hash(message)
      Utils.keccak256 message
    end

    def valid_s?(signature)
      s_value = Utils.v_r_s_for(signature).last
      s_value <= Secp256k1::N/2 && s_value != 0
    end

  end
end
