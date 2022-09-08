# lib/json_web_token.rb
require 'jwt'
require 'net/http'

class JsonWebToken
  class << self
    def algorithm
      'RS256'
    end

    def key(header)
      jwks_hash[header['kid']]
    end

    def jwks_hash
      jwks_raw = Net::HTTP.get URI("#{issuer}discovery/v2.0/keys")
      jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
      jwks_keys.map do |k|
        [
          k['kid'],
          OpenSSL::X509::Certificate.new(Base64.decode64(k['x5c'].first)).public_key
        ]
      end.to_h
    end

    def issuer
      ENV.fetch('AAD_DOMAIN', nil)
    end

    def audience
      ENV.fetch('AAD_AUDIENCE', nil)
    end

    def verify(token)
        JWT.decode(token, nil,
                   true, # Verify the signature of this token
                   algorithm: algorithm,
                   iss: issuer,
                   verify_iss: true,
                   aud: audience,
                   verify_aud: true) do |header|
          key(header)
        end
      end
  end
end