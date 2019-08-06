require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    class JWT
      class ClaimInvalid < StandardError; end
      class BadJwt < StandardError; end
      
      include OmniAuth::Strategy
      
      args [:secret]
      
      option :secret, nil
      option :algorithm, 'HS256'
      option :uid_claim, 'email'
      option :required_claims, %w(name email)
      option :info_map, {"name" => "name", "email" => "email"}
      option :auth_url, nil
      option :valid_within, nil
      option :verify, true
      
      def request_phase
        redirect options.auth_url
      end
      
      def decoded
        begin
          secret =
          case options.algorithm
          when *%w[RS256 RS384 RS512]
            OpenSSL::PKey::RSA.new(options.secret).public_key
          when *%w[ES256 ES384 ES512]
            OpenSSL::PKey::EC.new(options.secret).tap { |key| key.private_key = nil }
          when *%w(HS256 HS384 HS512)
            options.secret
          else
            raise NotImplementedError, "Unsupported algorithm: #{options.algorithm}"
          end

          @decoded ||= ::JWT.decode(request.params['jwt'], secret, options.verify, { algorithm: options.algorithm }).first
        rescue Exception => e
          raise BadJwt.new(e.message)
        end
        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]
        raise ClaimInvalid.new("'iat' timestamp claim is too skewed from present.") if options.valid_within && (Time.now.to_i - @decoded["iat"]).abs > options.valid_within
        @decoded
      end
      
      def callback_phase
        super
      rescue BadJwt => e
        fail! 'bad_jwt', e
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end
      
      uid{ decoded[options.uid_claim] }
      
      extra do
        {:raw_info => decoded}
      end
      
      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = decoded[v.to_s]
          h
        end
      end
    end
    
    class Jwt < JWT; end
  end
end
