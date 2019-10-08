require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Outlook < OmniAuth::Strategies::OAuth2
      BASE_MICROSOFT_GRAPH_URL = 'https://login.microsoftonline.com'

      option :name, :outlook

      def client
        if options.tenant_id
          tenant_id = options.tenant_id
        else
          tenant_id = 'common'
        end
        options.client_options.authorize_url = "#{BASE_MICROSOFT_GRAPH_URL}/#{tenant_id}/oauth2/v2.0/authorize"
        options.client_options.token_url = "#{BASE_MICROSOFT_GRAPH_URL}/#{tenant_id}/oauth2/v2.0/token"
        options.client_options.site = "#{BASE_MICROSOFT_GRAPH_URL}/#{tenant_id}/oauth2/v2.0/authorize"

        super
      end

      option :token_params, {
        resource: 'https://graph.microsoft.com/'
      }

      option :authorize_options, %i[display score auth_type scope prompt login_hint domain_hint response_mode]

      uid { raw_info["id"] }

      info do
        {
          'email' => raw_info["mail"],
          'first_name' => raw_info["givenName"],
          'last_name' => raw_info["surname"],
          'name' => [raw_info["givenName"], raw_info["surname"]].join(' '),
          'nickname' => raw_info["displayName"],
        }
      end

      extra do
        {
          'raw_info' => raw_info,
          'params' => access_token.params
        }
      end

      def raw_info
        @raw_info ||= access_token.get(authorize_params.resource + 'v1.0/me').parsed
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
            params[k] = options[k.to_s] unless [nil, ''].include?(options[k.to_s])
          end
        end
      end

    end
  end
end
