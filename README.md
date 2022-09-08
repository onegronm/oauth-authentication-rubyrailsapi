### Register calling and receiving services in AD

### config/local_env.yml
```yml
AAD_DOMAIN: ''
AAD_AUDIENCE: ''
```

### config/application.rb
```ruby
config.before_configuration do
    env_file = File.join(Rails.root, 'config', 'local_env.yml')
    YAML.load(File.open(env_file)).each do |key, value|
      ENV[key.to_s] = value
    end if File.exists?(env_file)
  end
```

### Gemfile
```Gemfile
gem "jwt"
gem "net-http"
```

```bash
bundle install
```

### json_web_token.rb
```ruby
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
```

### Application Controller
```ruby
def authorize!
    valid, result = verify(raw_token(request.headers))

    head :unauthorized unless valid

    @token ||= result
  end

  private

  def verify(token)
    payload, = JsonWebToken.verify(token)
    [true, payload]
  rescue JWT::DecodeError => e
    [false, e]
  end

  def raw_token(headers)
    return headers['Authorization'].split.last if headers['Authorization'].present?

    nil
  end
```

### Home Controller

```ruby
before_action :authorize!
```

### Requesting a token
The following HTTP POST requests an access token for the calling service. The client_id identifies the web service that requests the access token.

```curl
POST https://login.microsoftonline.com/{tenantId}/oauth2/token HTTP/1.1
Host: login.microsoftonline.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}=&resource={resource}
```
